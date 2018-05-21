package model

import (
	"os"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"github.com/PuerkitoBio/goquery"
	"github.com/xiak/matrix/pkg/common"
	"github.com/xiak/matrix/pkg/base/ship/engine"
	"github.com/xiak/matrix/pkg/common/logger"
)

type Status string

const (
	SUCCESS Status = "Success"
	FAILED Status = "Failed"
	// Downloader
	ErrDownloaderNotFound = "[404] The downloader not found"
	// Vol
	ErrVolNotFound = "[404] The vol was not found"
	ErrVolCoverNotFound = "[404] The vol cover (id=%s) was not found"
	ErrVolCoverDLailed = "[500] Downloading vol cover (id=%s) was failed"
	ErrVolCoverCLFFailed = "[500] Creating vol cover local file (id=%s) was failed"
	ErrVolIntroCLFFailed = "[500] Creating vol intro local file (id=%s) was failed"
	// MP3 Cover
	ErrMp3CoverNotFound = "[404] The mp3 cover (vid=%s, mid=%s) was not found"
	ErrMp3CoverDLailed = "[500] Downloading mp3 cover (vid=%s, mid=%s) failed"
	ErrMp3CoverCLFFailed = "[500] Create local file vol (vid=%s, mid=%s) cover failed"
	// MP3
	ErrMp3NotFound = "[404] The mp3 (vid=%s, mid=%s) was not found"
	ErrMp3DLailed = "[500] Download vol (vid=%s, mid=%s) cover failed"
	ErrMp3CLFFailed = "[500] Create local file vol (vid=%s, mid=%s) cover failed"
)

const (
	HomePath string = "http://www.luoo.net"
	VolPath string = "http://www.luoo.net/vol/index/%s"
	MusicPath string = "http://mp3-cdn2.luoo.net/low/luoo/radio%s/%s.mp3"
)

type LuooNet interface {}

type Luoo struct {
	localPath   string
	startVol 	uint64
	endVol 		uint64
	downloader  *engine.HttpEngine
}

type Vol struct {
	id 			string
	number  	string
	url     	string
	intro   	string
	title		string
	coverUrl	string
	tags 		string
	// 本地存储路径
	localPath	string
	// 本地存储文件夹名字
	localFolder string
	downloader  *engine.HttpEngine
}

type Music struct {
	id      	string
	url     	string
	title   	string
	artist  	string
	album   	string
	coverUrl	string
	// 本地存储路径
	localPath	string
	// 本地存储文件夹名字
	localFolder string
	downloader  *engine.HttpEngine
}

type ErrQueue struct {
	Vol 	*Vol
	Music	*Music
}

func NewLuoo(start uint64, end uint64) *Luoo {
	return &Luoo{
		localPath: 	"luoo",
		startVol:  	start,
		endVol: 	end,
		downloader: engine.DefaultHttpEngine(1, "致敬落网"),
	}
}

func (l *Luoo)SetDownloader(d *engine.HttpEngine) {
	l.downloader = d
}

func (l *Luoo)SetLocalPath(fp string) {
	l.localPath = fp
}

func (l *Luoo)SetVolRange(start uint64, end uint64) {
	l.startVol = start
	l.endVol = end
}

func (l *Luoo)Download() {
	if l.downloader == nil {
		logger.Log.Fatal(ErrDownloaderNotFound)
	}
	var i uint64
	for i = l.startVol; i <= l.endVol; i++ {
		vol := NewVol(strconv.FormatUint(i, 10))
		vol.SetLocalPath(l.localPath)
		vol.SetDownloader(l.downloader)
		vol.Parser()
	}
}

func NewVol(id string) *Vol {
	return &Vol{
		id:		id,
		url: 	fmt.Sprintf(VolPath, id),
	}
}

func (v *Vol)SetLocalPath(fp string) {
	v.localPath = fp
}

func (v *Vol)SetDownloader(d *engine.HttpEngine) {
	v.downloader = d
}

func (v *Vol)SetUrl(id string) {
	v.url = fmt.Sprintf(VolPath, id)
}

func (v *Vol)Print(format string, a ...interface{}) {
	logger.Zap.Infos(fmt.Sprintf(format, a...))
}

func (v *Vol)PrintRaw(status Status, format string, a ...interface{}) {
	zapFields := []zapcore.Field{
		zap.String("type", "vol"),
		zap.String("id", v.id),
		zap.String("number", v.number),
		zap.String("title", v.title),
		zap.String("cover", v.coverUrl),
		zap.String("url", v.url),
		zap.String("intro", v.intro),
	}
	if status == SUCCESS {
		logger.Zap.Infos(fmt.Sprintf(format, a...),
			zapFields...,
		)
	} else {
		logger.Zap.Errors(fmt.Sprintf(format, a...),
			zapFields...,
		)
	}
}
//func (v *Vol)Downloader(url string) error {
//	v.Print("Vol downloader started")
//	v.localFolder = fmt.Sprintf("%s.%s", v.id, v.title)
//	// 同一个Vol信息都会下载到相同的文件夹中
//	filePath := path.Join(v.localPath, v.localFolder)
//	os.MkdirAll(filePath, 0755)
//	// 下载vol cover图片
//	coverPath := path.Join(filePath, fmt.Sprintf("%s.jpg", v.title))
//	err := v.downloader.Download("GET", url, coverPath)
//	if err != nil {
//		v.PrintRaw(FAILED, "Downloading vol cover failed: %s", err.Error())
//		return err
//	}
//	v.Print("Success")
//}
func (v *Vol)Parser() {
	v.Print("Vol parser started")
	// GET http://www.luoo.net/vol/index/:id
	doc, err := v.downloader.Parser("GET", v.url)
	if err != nil {
		v.PrintRaw(FAILED, "[GET] vol url failed: %s", err.Error())
		return
	}

	// Parser: Get vol number
	v.number = doc.Find("span.vol-number").Text()
	// Parser: Get vol tags
	doc.Find("div.vol-tags").Each(func(i int, s *goquery.Selection) {
		v.tags = fmt.Sprintf("%s#%s", v.tags, s.Find("a.vol-tag-item").Text())
	})
	v.tags, err = common.ReviseFileName(v.tags, 128)
	if err != nil {
		v.PrintRaw(FAILED, "Revising vol tags string failed: %s", err.Error())
		return
	}
	// Parser: Get vol title
	v.title = doc.Find("span.vol-title").Text()
	v.title, err = common.ReviseFileName(v.title, 128)
	if err != nil {
		v.PrintRaw(FAILED, "Revising vol title string failed: %s", err.Error())
		return
	}
	// Parser: Get vol intro
	v.intro = strings.TrimSpace(doc.Find("div.vol-desc").Text())
	var isExist bool
	v.coverUrl, isExist = doc.Find("img.vol-cover").Attr("src")
	if !isExist {
		v.PrintRaw(FAILED, ErrVolNotFound)
		return
	}
	v.PrintRaw(SUCCESS, "Vol info")


	v.Print("Downloading vol cover")
	v.localFolder = fmt.Sprintf("%s.%s", v.id, v.title)
	// 同一个Vol信息都会下载到相同的文件夹中
	filePath := path.Join(v.localPath, v.localFolder)
	os.MkdirAll(filePath, 0755)
	// 下载vol cover图片
	coverPath := path.Join(filePath, fmt.Sprintf("%s.jpg", v.title))
	err = v.downloader.Download("GET", v.coverUrl, coverPath)
	if err != nil {
		v.PrintRaw(FAILED, "Downloading vol cover failed: %s", err.Error())
		return
	}
	v.Print("Success")

	v.Print("Writing vol intro to file")
	introPath := path.Join(filePath, fmt.Sprintf("%s.txt", v.title))
	fp, err := os.Create(introPath)
	defer fp.Close()
	if err != nil {
		v.PrintRaw(FAILED, "Creating vol intro file failed: %s", err.Error())
		return
	}
	_, err = fp.WriteString(fmt.Sprintf("Title: %s\nNumber: %s\nTags: %s\nIntro:\n%s\nMuisc List:\n",
		v.title, v.number, v.tags, v.intro))
	if err != nil {
		v.PrintRaw(FAILED, "Downloading vol intro failed: %s", err.Error())
		return
	}
	v.Print("Success")

	// 下载页面中的music
	doc.Find("li.track-item").Each(func(i int, s *goquery.Selection) {
		title := s.Find("a.trackname").Text()
		id := strings.Split(title, ".")[0]
		m := NewMusic(v.number, id)
		// For each item found, get the band and title
		m.title = title
		m.id = id
		m.title, err = common.ReviseFileName(m.title, 128)
		m.Print("Music parser started")
		if err != nil {
			m.PrintRaw(FAILED, "Revising music file name string failed: %s", err.Error())
			return
		}
		artist := strings.Split(s.Find("p.artist").Text(), ":")
		if len(artist) < 2 {
			m.PrintRaw(FAILED, "Parsing music artist failed: %s", artist)
			return
		}
		m.artist = artist[1]
		album := strings.Split(s.Find("p.album").Text(), ":")
		if len(album) < 2 {
			m.PrintRaw(FAILED, "Parsing music album failed: %s", album)
			return
		}
		m.album = album[1]
		m.coverUrl, isExist = s.Find("a.btn-action-share").Attr("data-img")
		if !isExist {
			m.PrintRaw(FAILED, "Parsing music cover failed: %s, Can't found cover url", m.coverUrl)
			return
		}
		_, err = fp.WriteString(fmt.Sprintf("%s\n", m.title))
		if err != nil {
			m.PrintRaw(FAILED, "Writing music list to file failed: %s, %s", m.title, err.Error())
			return
		}
		m.Print("Downloading music cover")
		// 下载vol cover图片
		coverPath := path.Join(filePath, fmt.Sprintf("%s.jpg", m.title))
		err = v.downloader.Download("GET", m.coverUrl, coverPath)
		if err != nil {
			m.PrintRaw(FAILED, "Downloading music cover failed: %s, %s", m.coverUrl, err.Error())
			return
		}
		m.Print("Downloading music cover successfully")

		m.Print("Downloading mp3 file")
		// 下载mp3
		mp3Path := path.Join(filePath, fmt.Sprintf("%s.mp3", m.title))
		// http://mp3-cdn2.luoo.net/low/luoo/radio00x/0x.mp3
		err = v.downloader.Download("GET", m.url, mp3Path)
		if err == nil {
			m.PrintRaw(SUCCESS, "Downloading mp3 file successfully")
			return
		}
		// http://mp3-cdn2.luoo.net/low/luoo/radiox/0x.mp3
		vNumber := IntelligentId(v.number, 1)
		m.SetUrl(vNumber, m.id)
		err = v.downloader.Download("GET", m.url, mp3Path)
		if err == nil {
			m.PrintRaw(SUCCESS, "Downloading mp3 file successfully")
			return
		}
		// http://mp3-cdn2.luoo.net/low/luoo/radio0x/x.mp3
		mId := IntelligentId(m.id, 1)
		m.SetUrl(v.number, mId)
		err = v.downloader.Download("GET", m.url, mp3Path)
		if err == nil {
			m.PrintRaw(SUCCESS, "Downloading mp3 file successfully")
			return
		}
		// http://mp3-cdn2.luoo.net/low/luoo/radiox/x.mp3
		m.SetUrl(vNumber, mId)
		err = v.downloader.Download("GET", m.url, mp3Path)
		if err == nil {
			m.PrintRaw(SUCCESS, "Downloading mp3 file successfully")
			return
		}
		m.PrintRaw(FAILED, "Downloading mp3 file failed: %s", err.Error())
	})
}

/**
 * @vol vol number
 * @id music id
 */
func NewMusic(vol string, id string) *Music {
	return &Music{
		id:     id,
		url: 	fmt.Sprintf(MusicPath, vol, id),
	}
}

func (m *Music)SetUrl(vol string, id string) {
	m.url = fmt.Sprintf(MusicPath, vol, id)
}

func (m *Music)Print(format string, a ...interface{}) {
	logger.Zap.Infos(fmt.Sprintf(format, a...))
}

func (m *Music)PrintRaw(status Status, format string, a ...interface{}) {
	zapFields := []zapcore.Field{
		zap.String("type", "music"),
		zap.String("title", m.title),
		zap.String("artist", m.artist),
		zap.String("album", m.album),
		zap.String("cover", m.coverUrl),
	}
	if status == SUCCESS {
		logger.Zap.Infos(fmt.Sprintf(format, a...),
			zapFields...,
		)
	} else {
		logger.Zap.Errors(fmt.Sprintf(format, a...),
			zapFields...,
		)
	}
}


// Id must be like 090 or 00001
func IntelligentId(id string, length uint8) string {
	re, _ := regexp.Compile("^0*")
	id = re.ReplaceAllString(id, "")
	format := "%0" + strconv.Itoa(int(length)) + "s"
	id = fmt.Sprintf(format, id)
	return id
}
