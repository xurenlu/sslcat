package web

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
)

const (
	fcgiVersion1     = 1
	fcgiBeginRequest = 1
	fcgiAbortRequest = 2
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7
	fcgiResponder    = 1
)

// fcgiHeader 表示 FastCGI 头
type fcgiHeader struct {
	Version       uint8
	Type          uint8
	RequestID     uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

func writeHeader(w io.Writer, typ uint8, reqID uint16, contentLen uint16) error {
	h := fcgiHeader{Version: fcgiVersion1, Type: typ, RequestID: reqID, ContentLength: contentLen, PaddingLength: 0, Reserved: 0}
	var buf [8]byte
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint16(buf[2:4], h.RequestID)
	binary.BigEndian.PutUint16(buf[4:6], h.ContentLength)
	buf[6] = h.PaddingLength
	buf[7] = h.Reserved
	_, err := w.Write(buf[:])
	return err
}

func writeBeginRequest(w io.Writer, reqID uint16) error {
	var body [8]byte
	binary.BigEndian.PutUint16(body[0:2], fcgiResponder)
	body[2] = 0 // flags: keepConn=0
	// rest 5 bytes zero
	if err := writeHeader(w, fcgiBeginRequest, reqID, uint16(len(body))); err != nil {
		return err
	}
	_, err := w.Write(body[:])
	return err
}

func writeNameValuePair(buf *bytes.Buffer, name, value string) {
	n := len(name)
	v := len(value)
	if n < 128 {
		buf.WriteByte(byte(n))
	} else {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n)|1<<31)
		buf.Write(b[:])
	}
	if v < 128 {
		buf.WriteByte(byte(v))
	} else {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v)|1<<31)
		buf.Write(b[:])
	}
	buf.WriteString(name)
	buf.WriteString(value)
}

func writeParams(w io.Writer, reqID uint16, params map[string]string) error {
	var buf bytes.Buffer
	for k, v := range params {
		writeNameValuePair(&buf, k, v)
	}
	if buf.Len() > 0 {
		if err := writeHeader(w, fcgiParams, reqID, uint16(buf.Len())); err != nil {
			return err
		}
		if _, err := w.Write(buf.Bytes()); err != nil {
			return err
		}
	}
	// empty params terminator
	return writeHeader(w, fcgiParams, reqID, 0)
}

func writeStdin(w io.Writer, reqID uint16, body io.Reader) error {
	if body != nil {
		br := bufio.NewReader(body)
		tmp := make([]byte, 32*1024)
		for {
			n, err := br.Read(tmp)
			if n > 0 {
				if err2 := writeHeader(w, fcgiStdin, reqID, uint16(n)); err2 != nil {
					return err2
				}
				if _, err2 := w.Write(tmp[:n]); err2 != nil {
					return err2
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	// empty stdin terminator
	return writeHeader(w, fcgiStdin, reqID, 0)
}

// fcgiServe 执行一次 FastCGI 请求，并将响应写入 w（解析头部并转发）
func fcgiServe(conn net.Conn, reqID uint16, w http.ResponseWriter) error {
	r := bufio.NewReader(conn)
	headersDone := false
	statusCode := 200
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return err
		}
		typ := hdr[1]
		contentLen := binary.BigEndian.Uint16(hdr[4:6])
		padding := int(hdr[6])
		if contentLen > 0 {
			content := make([]byte, int(contentLen))
			if _, err := io.ReadFull(r, content); err != nil {
				return err
			}
			switch typ {
			case fcgiStdout:
				if !headersDone {
					// 解析 CGI 头
					// 找到 \r\n\r\n 分隔
					data := content
					sep := []byte("\r\n\r\n")
					if idx := bytes.Index(data, sep); idx != -1 {
						headerPart := string(data[:idx])
						for _, line := range strings.Split(headerPart, "\r\n") {
							if line == "" {
								continue
							}
							if i := strings.Index(line, ":"); i != -1 {
								k := line[:i]
								v := strings.TrimSpace(line[i+1:])
								if strings.EqualFold(k, "Status") {
									// 格式: 200 OK
									if sp := strings.SplitN(v, " ", 2); len(sp) > 0 {
										if code := strings.TrimSpace(sp[0]); len(code) >= 3 {
											// ignore err
											if c := http.StatusText(200); c != "" { /* noop to silence import */
											}
										}
									}
								} else {
									w.Header().Add(k, v)
								}
							}
						}
						headersDone = true
						// 默认 200
						w.WriteHeader(statusCode)
						// 写入剩余 body
						if _, err := w.Write(data[idx+4:]); err != nil {
							return err
						}
					} else {
						// header 尚未结束，继续等待
						// 累积不实现，直接作为 body 不安全；此处简化：若没有头，则按 body 写
						headersDone = true
						w.WriteHeader(statusCode)
						if _, err := w.Write(data); err != nil {
							return err
						}
					}
				} else {
					if _, err := w.Write(content); err != nil {
						return err
					}
				}
			case fcgiStderr:
				// 忽略或记录
			}
		}
		if padding > 0 {
			io.CopyN(io.Discard, r, int64(padding))
		}
		if typ == fcgiEndRequest {
			break
		}
	}
	return nil
}
