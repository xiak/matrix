package equipment

import (
	"os"
	"io"
	"io/ioutil"
	"net/http"
	"fmt"
	"errors"
	"sync"
	"net"
	"strings"
	"time"
	"bufio"
	"crypto/tls"
	"github.com/xiak/matrix/pkg/ship"
	"github.com/xiak/matrix/pkg/common"
)

const (
	ErrTypeByteSlice = "Type Assertion err: Type must be []byte "
	ErrTypeHttpResponse = "Type Assertion err: Type must be *http.Response "
	ErrNilSpoil = "Spoil take a nil *http.Response "
	ErrType = "Unknown type "
	Err404NotFound = "(404) Page not found "
)

/**
 * Http
 */
type HttpWeapon struct {
	id      		uint64
	name    		string
	// HTTP Header
	header  		http.Header
	// HTTP Body
	body 			io.Reader
	spoil    		ship.Spoil
	// Sets timeout for dialing
	dialTimeout 	time.Duration
	// Set read and write deadlines
	connectTimeout 	time.Duration
	// Retry times
	retries			int
	// Retry duration
	retryDuration 	time.Duration
	// Redirect times
	redirects 		int
	// Description
	desc 			string

	client 			*http.Client
}

// 默认的http engine
func DefaultHttpWeapon(id uint64, name string) (w *HttpWeapon) {
	w = &HttpWeapon{
		id:				id,
		name:			name,
		redirects: 		0,
		retries:        3,
		retryDuration:  1*time.Second,
		dialTimeout: 	5*time.Second,
		connectTimeout: 1*time.Minute,
	}
	// Closed connection after finished
	if w.header == nil {
		w.header = make(http.Header)
	}
	w.header.Set("Connection", "close")
	return
}

// 设置引擎编号
func (w *HttpWeapon)SetId(id uint64) {
	w.id = id
}
// 获取引擎编号
func (w *HttpWeapon)GetId() uint64 {
	return w.id
}

// 设置引擎启动失败时的尝试重启次数
func (w *HttpWeapon)SetRetryTimes(num int) {
	w.retries = num
}

// 获取引擎启动失败时的尝试重启次数
func (w *HttpWeapon)GetRetryTimes() int {
	return w.retries
}

// 设置正常启动引擎的时间限制，超过即为失败
func (w *HttpWeapon)SetDialTimeout(d time.Duration) {
	w.dialTimeout = d
}

// 获取引擎正常启动时间限制
func (w *HttpWeapon)GetDialTimeout() time.Duration {
	return w.dialTimeout
}

// 设置引擎失去响应最长时间，超过后引擎会停止
func (w *HttpWeapon)SetConnTimeout(d time.Duration) {
	w.connectTimeout = d
}

// 获取引擎失去响应最长时间
func (w *HttpWeapon)GetConnTimeout() time.Duration {
	return w.connectTimeout
}

// 获取引擎描述
func (w *HttpWeapon)SetDescription(desc string) {
	w.desc = desc
}

// 获取引擎描述
func (w *HttpWeapon)GetDescription() string {
	return w.desc
}

// 启动引擎
// @method Http method: GET, POST, HEADER ...
// @target Http url
// @resp *http.Response
// @err nil or error
func (w *HttpWeapon) Fire(method string, target string) (ship.Spoil, error) {
	if w.client == nil {
		w.client = NewHttpClient(w.redirects)
	}

	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, w.dialTimeout)
			if err != nil {
				return nil, err
			}
			if w.connectTimeout > 0 {
				c.SetDeadline(time.Now().Add(w.connectTimeout))
			}
			return c, nil
		},
	}

	// Skip verify insecure link
	u, err := common.UrlEncode(target)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) == "https" {
		transport.TLSClientConfig = &tls.Config{RootCAs: nil, InsecureSkipVerify: true}
		transport.DisableCompression = true
	}
	w.client.Transport = transport

	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}

	req.Header = w.header

	// If request failed. retry
	var resp *http.Response
	if w.retries > 0 {
		for i := 0; i < w.retries; i++ {
			resp, err = w.client.Do(req)
			if err == nil {
				break
			}
			time.Sleep(w.retryDuration)
		}
	} else {
		resp, err = w.client.Do(req)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		return nil, errors.New(fmt.Sprintf("%s: %s", Err404NotFound, target))
	}
	w.spoil = DefaultHttpSpoil(target)
	w.spoil.Store(resp)
	return w.spoil, nil
}

/**
 * Http
 */
type HttpCollector struct {
	res 			*http.Response
	storage 		[]byte

	progress		bool
	length      	int64
	current     	int

	sync.Mutex
}

func DefaultHttpCollector(v *http.Response) (*HttpCollector, error) {
	return &HttpCollector{
		// Disable progress bar
		progress:	false,
		res:		v,
	}, nil
}

// 显示下载进度条
func (c *HttpCollector)EnableProgress() {
	c.progress = true
}
// 禁止下载进度条
func (c *HttpCollector)DisableProgress() {
	c.progress = false
}

// Collect spoil to files
// @to file path
func (c *HttpCollector)Collect(to string) (b ship.Spoil, err error) {
	defer func(){
		io.Copy(ioutil.Discard, c.res.Body)
		c.res.Body.Close()
	}()

	c.length = c.res.ContentLength
	if c.length <= 0 {
		c.storage = make([]byte, 0)
	} else {
		c.storage = make([]byte, c.length)
	}
	if c.progress {
		reader := bufio.NewReader(c.res.Body)
		for {
			current, err := reader.Read(c.storage)
			c.current += current
			if err == io.EOF {
				break
			}
		}
	} else {
		payload, err := ioutil.ReadAll(c.res.Body)
		if err != nil {
			return	nil, err
		}
		c.storage = payload
	}
	spoil := DefaultHttpSpoil(to)
	spoil.Store(c.storage)
	return spoil, nil
}

type HttpSpoil struct {
	Url     string
	Storage interface{}
}

func DefaultHttpSpoil(u string) *HttpSpoil{
	return &HttpSpoil{
		Url:    	u,
	}
}

func (s *HttpSpoil)Store(w interface{}) {
	s.Storage = w
}

func (s *HttpSpoil)Take() (interface{}, error) {
	if s.Storage == nil {
		return nil, errors.New(ErrNilSpoil)
	}
	return s.Storage, nil
}

func (s *HttpSpoil)GetCourse() string {
	return s.Url
}

type HttpTransformer struct {
	Course  string
	Storage []byte
}

func DefaultHttpTransformer(v []byte) (*HttpTransformer, error) {
	return &HttpTransformer{
		Storage: v,
	}, nil
}

func (c *HttpTransformer)File(to string) (err error) {
	fp, err := os.Create(to)
	defer fp.Close()
	if err != nil {
		return
	}
	err = ioutil.WriteFile(to, c.Storage, 0666)

	return err
}

func NewHttpClient(redirects int) *http.Client {
	client := &http.Client{
		/**
		 * 1. If redirects is 0, the Client uses its default policy,
		 * which is to stop after 10 consecutive requests.
		 * 2. If redirects less than 0, not allowed to rediect
		 */
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if redirects == 0 {
				return nil
			}
			if redirects < 0 {
				return fmt.Errorf("Not allowed to redirects ")
			}
			if len(via) >= redirects {
				return fmt.Errorf("Stopped redirects after %v times ", redirects)
			}
			return nil
		},
	}
	return client
}



