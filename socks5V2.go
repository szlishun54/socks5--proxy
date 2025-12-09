package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 代理服务器监听地址
const SOCKS5_SERVER_ADDR = "0.0.0.0:1080"

// 转发服务器地址
const FORWARD_SERVER_ADDR = "196.3.251.16:1081"

//const FORWARD_SERVER_ADDR = "127.0.0.1:1081"

// SOCKS5 协议的常量
const (
	SOCKS_VERSION = 0x05 // SOCKS5 版本号
	AUTH_NO_AUTH  = 0x00 // 无认证方式
	CMD_CONNECT   = 0x01 // CONNECT 命令
	ATYPE_IPV4    = 0x01 // IPv4 地址类型
	ATYPE_DOMAIN  = 0x03 // 域名地址类型
)

const keyStr = "0123456789abcdef" // 16字节密钥 (AES-128)
var key = []byte(keyStr)

var iv = []byte("fedcba9876543210") //noice字节

func encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

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
	fmt.Printf("SOCKS5 代理服务器正在监听 %s\n", SOCKS5_SERVER_ADDR)

	listener, err := net.Listen("tcp", SOCKS5_SERVER_ADDR)
	if err != nil {
		fmt.Printf("监听失败: %v\n", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("接受连接失败: %v\n", err)
			continue
		}

		// 为每个新连接启动一个 Goroutine 处理
		go handleConnection(conn)
	}
}

// 处理客户端连接
func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 1. 握手阶段 (读取并响应版本和认证方法)
	// 客户端发送: [VER|NMETHODS|METHODS...]
	if err := socks5Handshake(clientConn); err != nil {
		fmt.Printf("SOCKS5 握手失败: %v\n", err)
		return
	}

	targetConn, err := socks5Request(clientConn)

	if err != nil {
		// 响应错误: REP = 0x04 (主机不可达) 或 0x05 (连接被拒绝)

		fmt.Println("连接代理服务器出错！%v", err)
		return
	}
	// targetConn 已经是与目标服务器建立的连接
	defer targetConn.Close()
	// 3. 数据转发阶段 (将数据在客户端和目标服务器之间双向转发)

	//fmt.Printf("成功连接并开始转发数据到 %s\n", targetConn.RemoteAddr())
	forwardData(clientConn, targetConn)
}

// 步骤 1: SOCKS5 握手和认证
func socks5Handshake(conn net.Conn) error {
	// 读取客户端的问候消息 (至少包含 3 字节: VER, NMETHODS)
	header := make([]byte, 258) // 足够大以容纳最大可能的握手包 (VER + NMETHODS + 255 METHODS)
	// 设置 5 秒超时，防止恶意或僵尸连接
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(header)
	if err != nil {
		return fmt.Errorf("读取握手头部失败: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) // 取消超时

	// 检查版本号
	if header[0] != SOCKS_VERSION {
		return fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}

	// 检查客户端是否支持 '无认证' 方式 (0x00)
	nMethods := int(header[1])
	supported := false
	for i := 0; i < nMethods; i++ {
		if header[2+i] == AUTH_NO_AUTH {
			supported = true
			break
		}
	}
	if !supported {
		// 响应: [VER|METHOD] -> 0x05 | 0xFF (不支持的方法)
		conn.Write([]byte{SOCKS_VERSION, 0xFF})
		return fmt.Errorf("客户端不支持无认证方式")
	}

	// 响应: [VER|METHOD] -> 0x05 | 0x00 (选择无认证)
	_, err = conn.Write([]byte{SOCKS_VERSION, AUTH_NO_AUTH})
	return err
}

// 步骤 2: 处理 SOCKS5 请求，连接到目标服务器
func socks5Request(clientConn net.Conn) (net.Conn, error) {
	// 请求格式: [VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT]
	// 读取请求的前 4 个字节 (VER|CMD|RSV|ATYP)
	header := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return nil, fmt.Errorf("读取请求头部失败: %w", err)
	}

	// 检查版本和命令
	if header[0] != SOCKS_VERSION {
		return nil, fmt.Errorf("不支持的 SOCKS 版本: %d", header[0])
	}
	if header[1] != CMD_CONNECT {
		// 响应错误: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
		// REP = 0x07 (命令不支持)
		clientConn.Write([]byte{SOCKS_VERSION, 0x07, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
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
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			return nil, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		host = net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	case ATYPE_DOMAIN:
		// 域名: 1 字节长度 + 域名
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lenByte); err != nil {
			return nil, fmt.Errorf("读取域名长度失败: %w", err)
		}
		domainLen := int(lenByte[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			return nil, fmt.Errorf("读取域名失败: %w", err)
		}
		host = string(domain)
	default:
		// 响应错误: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
		// REP = 0x08 (地址类型不支持)
		clientConn.Write([]byte{SOCKS_VERSION, 0x08, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// 读取 2 字节端口
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBytes); err != nil {
		return nil, fmt.Errorf("读取端口失败: %w", err)
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Printf("接收到连接请求: %s -> %s\n", clientConn.RemoteAddr(), targetAddr)

	// 尝试连接目标服务器
	targetConn, err := net.DialTimeout("tcp", FORWARD_SERVER_ADDR, 5*time.Second)

	if err != nil {
		// 响应错误: REP = 0x04 (主机不可达) 或 0x05 (连接被拒绝)
		clientConn.Write([]byte{SOCKS_VERSION, 0x04, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return nil, fmt.Errorf("连接目标 %s 失败: %w", targetAddr, err)
	}
	encrypted, err := encrypt([]byte(targetAddr), key)
	n, err := targetConn.Write([]byte(encrypted))
	if err != nil || n != len(encrypted) {
		targetConn.Close()
		return nil, fmt.Errorf("发送目标地址 %s 失败: %w", targetAddr, err)
	}
	// 响应成功: [VER|REP|RSV|ATYP|BND.ADDR|BND.PORT]
	// REP = 0x00 (成功)
	// 这里的 BND.ADDR 和 BND.PORT 应该是代理服务器实际使用的绑定地址和端口
	net.SplitHostPort(targetConn.LocalAddr().String())

	// 简单起见，这里直接使用 0.0.0.0:0 作为绑定地址响应
	// 实际应用中需要解析并发送正确的地址和端口
	resp := []byte{SOCKS_VERSION, 0x00, 0x00, ATYPE_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := clientConn.Write(resp); err != nil {
		targetConn.Close()
		return nil, fmt.Errorf("发送连接成功响应失败: %w", err)
	}

	return targetConn, nil
}

// 步骤 3: 双向数据转发
func forwardData(client net.Conn, target net.Conn) {
	// 使用 io.Copy 在两个连接之间双向复制数据

	// 从客户端到目标服务器
	go func() {
		encryptedWriter, err := NewEncryptWriter(target, key, iv)
		if err != nil {
			// 错误处理
		}
		// 2. 将 clientConn 的数据复制到加密 writer (数据被加密后发送给 targetConn)
		_, err = io.Copy(encryptedWriter, client)
		if err != nil && err != io.EOF {
			// fmt.Printf("客户端 -> 目标转发出错: %v\n", err)
		}
		// 关闭目标连接的写入端，通知对方数据已发送完毕
		target.(*net.TCPConn).CloseWrite()
	}()

	// 从目标服务器到客户端
	//_, err := io.Copy(client, target)
	decryptedReader, err := NewDecryptReader(target, key, iv)
	if err != nil {
		// 错误处理
	}
	// 2. 将解密 reader 的数据复制到 targetConn (解密后的明文发送给 targetConn)
	_, err = io.Copy(client, decryptedReader)
	if err != nil && err != io.EOF {
		// fmt.Printf("目标 -> 客户端转发出错: %v\n", err)
	}
	// 关闭客户端连接的写入端
	client.(*net.TCPConn).CloseWrite()
}
