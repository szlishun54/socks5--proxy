package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// 定义服务器监听的地址和端口
const (
	CONN_HOST = "0.0.0.0"
	CONN_PORT = "1081"
	CONN_TYPE = "tcp"
)

const (
	SOCKS_VERSION = 0x05 // SOCKS5 版本号
	AUTH_NO_AUTH  = 0x00 // 无认证方式
	CMD_CONNECT   = 0x01 // CONNECT 命令
	ATYPE_IPV4    = 0x01 // IPv4 地址类型
	ATYPE_DOMAIN  = 0x03 // 域名地址类型
)

const keyStr = "0123456789abcdef" // 16字节密钥 (AES-128)
var key = []byte(keyStr)

var iv = []byte("fedcba9876543210")

func decrypt(ciphertext string, key []byte) ([]byte, error) {
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertextBytes) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertextBytes[:aes.BlockSize]
	ciphertextBytes = ciphertextBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertextBytes, ciphertextBytes)
	return ciphertextBytes, nil
}

// NewEncryptWriter 将 net.Conn (w) 封装成一个加密的 io.Writer
func NewEncryptWriter(w io.Writer, key, iv []byte) (io.Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 创建一个 CFB 加密流
	stream := cipher.NewCFBEncrypter(block, iv)
	// 使用 cipher.StreamWriter 封装底层连接
	return &cipher.StreamWriter{S: stream, W: w}, nil
}

// NewDecryptReader 将 net.Conn (r) 封装成一个解密的 io.Reader
func NewDecryptReader(r io.Reader, key, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 创建一个 CFB 解密流
	stream := cipher.NewCFBDecrypter(block, iv)
	// 使用 cipher.StreamReader 封装底层连接
	return &cipher.StreamReader{S: stream, R: r}, nil
}

func main() {
	// 步骤 1: 监听传入连接
	// net.Listen 返回一个 Listener 接口，用于接受连接
	listener, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		log.Fatal("Error listening:", err.Error())
	}
	defer listener.Close() // 确保程序退出时关闭监听器

	log.Printf("Listening on %s:%s using %s protocol", CONN_HOST, CONN_PORT, CONN_TYPE)

	// 步骤 2: 循环接受连接
	for {
		// listener.Accept() 阻塞等待客户端连接
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting:", err.Error())
			continue
		}

		// 步骤 3: 启动 Go routine 处理连接
		// 使用 Go routine 可以同时处理多个客户端连接，实现并发
		go handleRequest(conn)
	}
}

// handleRequest 处理单个客户端连接的读写操作
func handleRequest(conn net.Conn) {
	// 确保连接在函数结束时关闭
	defer conn.Close()
	host := make([]byte, 512)
	n, _ := conn.Read(host)
	decrypted, err := decrypt(string(host[:n]), key)
	fmt.Println("%dHost%s", n, string(decrypted))
	//targetConn, err := socks5Request(conn)
	targetConn, err := net.DialTimeout("tcp", string(decrypted), 5*time.Second)
	if err != nil {
		log.Printf("SOCKS5 request error: %v", err)
		return
	}
	defer targetConn.Close()
	forwardData(conn, targetConn)
}

func socks5Request(clientConn net.Conn) (net.Conn, error) {
	// 请求格式: [VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT]
	// 读取请求的前 4 个字节 (VER|CMD|RSV|ATYP)
	decryptedReader, err := NewDecryptReader(clientConn, key, iv)
	encryptedWriter, err := NewEncryptWriter(clientConn, key, iv)
	header := make([]byte, 4)
	if _, err := io.ReadFull(decryptedReader, header); err != nil {
		return nil, fmt.Errorf("读取请求头部失败: %w", err)
	}

	// 检查版本和命令
	if header[0] != SOCKS_VERSION {
		return nil, fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}
	if header[1] != CMD_CONNECT {
		// 响应错误: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
		// REP = 0x07 (命令不支持)
		encryptedWriter.Write([]byte{SOCKS_VERSION, 0x07, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, fmt.Errorf("不支持的命令: %d, 只支持 CONNECT(0x01)", header[1])
	}
	// 忽略 RSV (保留字段)

	// 读取目标地址和端口
	var host string
	addrType := header[3]

	switch addrType {
	case ATYPE_IPV4:
		// IPv4: 4 字节地址
		addr := make([]byte, 4)
		if _, err := io.ReadFull(decryptedReader, addr); err != nil {
			return nil, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		host = net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	case ATYPE_DOMAIN:
		// 域名: 1 字节长度 + 域名
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(decryptedReader, lenByte); err != nil {
			return nil, fmt.Errorf("读取域名长度失败: %w", err)
		}
		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(decryptedReader, domain); err != nil {
			return nil, fmt.Errorf("读取域名失败: %w", err)
		}
		host = string(domain)
	default:
		// 响应错误: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
		// REP = 0x08 (地址类型不支持)
		encryptedWriter.Write([]byte{SOCKS_VERSION, 0x08, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// 读取 2 字节端口
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(decryptedReader, portBytes); err != nil {
		return nil, fmt.Errorf("读取端口失败: %w", err)
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Printf("接收到连接请求: %s -> %s\n", clientConn.RemoteAddr(), targetAddr)

	// 尝试连接目标服务器
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		// 响应错误: REP = 0x04 (主机不可达) 或 0x05 (连接被拒绝)
		encryptedWriter.Write([]byte{SOCKS_VERSION, 0x04, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, fmt.Errorf("连接目标 %s 失败: %w", targetAddr, err)
	}

	// 响应成功: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
	// REP = 0x00 (成功)
	// 这里的 BND.ADDR 和 BND.PORT 应该是代理服务器实际使用的绑定地址和端口
	net.SplitHostPort(targetConn.LocalAddr().String())

	// 简单起见，这里直接使用 0.0.0.0:0 作为绑定地址响应
	// 实际应用中需要解析并发送正确的地址和端口
	resp := []byte{SOCKS_VERSION, 0x00, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := encryptedWriter.Write(resp); err != nil {
		targetConn.Close()
		return nil, fmt.Errorf("发送连接成功响应失败: %w", err)
	}

	return targetConn, nil
}

func forwardData(client net.Conn, target net.Conn) {
	// 使用 io.Copy 在两个连接之间双向复制数据

	// 从客户端到目标服务器
	go func() {
		decryptedReader, _ := NewDecryptReader(client, key, iv)
		_, err := io.Copy(target, decryptedReader)
		if err != nil && err != io.EOF {
			// fmt.Printf("客户端 -> 目标转发出错: %v\n", err)
		}
		// 关闭目标连接的写入端，通知对方数据已发送完毕
		target.(*net.TCPConn).CloseWrite()
	}()

	// 从目标服务器到客户端
	encryptedWriter, err := NewEncryptWriter(client, key, iv)
	_, err = io.Copy(encryptedWriter, target)
	if err != nil && err != io.EOF {
		// fmt.Printf("目标 -> 客户端转发出错: %v\n", err)
	}
	// 关闭客户端连接的写入端
	client.(*net.TCPConn).CloseWrite()
}
