package main

import (
	"fmt"
	"strings"
	"github.com/PuerkitoBio/goquery"
	"github.com/xiak/matrix/pkg/base/ship/engine"
	"github.com/xiak/matrix/pkg/common/logger"
	"strconv"
	"path"
	"os"
	"io"
)

const (
	VOL404 		string = "404: Vol (id=%s) not found."
	VOLCOVER404 string = "404: Vol Cover Link (id=%s) not found: %s"
	DOWNLOADCOVERFAIL string = "500: Download Vol Cover (id=%s) failed: %s"
	CREATEVOLCOVERFAIL string = "500: Create Vol Cover File (id=%s) failed: %s"
	DOWNLOADMP3FAIL string = "500: Download Mp3 (vid=%s, mid=%s) failed: %s"
	CREATEMP3FAIL string = "500: Create Mp3 File (vid=%s, mid=%s) failed: %s"
	MUSIC404 	string = "404: Music (vid=%s, mid=%s) not found."
)


type Luoo struct {
	Home 	string
	Vol 	string
	Music 	string
	// Start Vol Id
	Start   uint64
	// End Vol id
	End     uint64
	downloader  *engine.HttpEngine
	DownPath 	string
}

type Vol struct {
	id 		string
	number  string
	url     string
	intro   string
	title	string
	cover	string
	total   uint64
	music	*Music
	downloader  *engine.HttpEngine
	introPath 	string
	coverPath 	string
}

type Music struct {
	id      string
	url     string
	title   string
	mp3     string
	artist  string
	album   string
	cover	string
	downloader  *engine.HttpEngine
	mp3Path 	string
	coverPath 	string

}

func NewLuoo(start uint64, end uint64) *Luoo {
	return &Luoo{
		Home: 		"http://www.luoo.net",
		Vol: 		"http://www.luoo.net/vol/index/%d",
		Start: 		start,
		End: 		end,
		DownPath:	"luoo",
	}
}

func (l *Luoo)SetDownloader() {
	l.downloader = engine.DefaultHttpEngine(1, "致敬落网")
}

func (l *Luoo)Download() {
	if l.downloader == nil {
		logger.Log.Fatal("You must set a downloader")
	}
	var i uint64
	for i = l.Start; i <= l.End; i++ {
		url := fmt.Sprintf(l.Vol, i)
		vol := NewVol()
		vol.SetId(strconv.FormatUint(i,10))
		vol.SetUrl(url)
		vol.SetPath(l.DownPath, l.DownPath)
		vol.SetDownloader(l.downloader)
		vol.Parser()
	}
}

func NewVol() *Vol {
	return &Vol{
	}
}
func (v *Vol)SetId(id string) {
	v.id = id
}

func (v *Vol)SetPath(introPath, coverPath string) {
	v.introPath = introPath
	v.coverPath = coverPath
}

func (v *Vol)SetUrl(url string) {
	v.url = url
}

func (v *Vol)SetDownloader(d *engine.HttpEngine) {
	v.downloader = d
}

func (v *Vol)Parser() {
	var isExist bool
	res, err := v.downloader.Start("GET", v.url)
	if err != nil {
		logger.Log.Errorf("Vol Parser: %s", err.Error())
		return
	}
	if res.StatusCode == 404 {
		logger.Log.Errorf(VOL404, v.id)
		return
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		logger.Log.Errorf(err.Error())
	}
	// Find the review items
	v.number = doc.Find("span.vol-number").Text()
	v.title = doc.Find("span.vol-title").Text()
	v.intro = strings.TrimSpace(doc.Find("div.vol-desc").Text())
	v.cover, isExist = doc.Find("img.vol-cover").Attr("src")
	if !isExist {
		logger.Log.Errorf(VOL404, v.id)
		return
	}
	v.Printer()
	res, err = v.downloader.Start("GET", v.cover)
	logger.Log.Info("Downloading vol cover...")
	if err != nil {
		logger.Log.Errorf(DOWNLOADCOVERFAIL, v.id, err.Error())
		return
	}
	if res.StatusCode == 404 {
		logger.Log.Errorf(VOLCOVER404, v.id, err.Error())
		return
	}
	filePath := path.Join(v.coverPath, fmt.Sprintf("%s.%s", v.id, v.title))
	os.MkdirAll(filePath, 0755)
	v.coverPath = path.Join(filePath, fmt.Sprintf("%s.jpg", v.title))
	cfp, err := os.Create(v.coverPath)
	if err != nil {
		logger.Log.Errorf(CREATEVOLCOVERFAIL, v.id, err.Error())
		return
	}
	_, err = io.Copy(cfp, res.Body)
	if err != nil {
		logger.Log.Errorf(CREATEVOLCOVERFAIL, v.id, err.Error())
	}
	logger.Log.Info("Downloading vol cover complete")
	logger.Log.Info("Writing intro...")
	v.introPath = path.Join(filePath, fmt.Sprintf("%s.txt", v.title))
	ifp, err := os.Create(v.introPath)
	defer ifp.Close()
	if err != nil {
		logger.Log.Errorf(CREATEVOLCOVERFAIL, v.id, err.Error())
		return
	}
	ifp.WriteString(fmt.Sprintf("%s\n", v.intro))
	if err != nil {
		logger.Log.Errorf(CREATEVOLCOVERFAIL, v.id, err.Error())
	}
	logger.Log.Info("Writing intro complete")
	doc.Find("li.track-item").Each(func(i int, s *goquery.Selection) {
		m := NewMusic()
		// For each item found, get the band and title
		m.title = s.Find("a.trackname").Text()
		title := strings.Split(m.title, ".")
		if len(title) < 2 {
			logger.Log.Errorf(MUSIC404, v.id, title[0])
			return
		}
		m.id = title[0]
		artist := strings.Split(s.Find("p.artist").Text(), ":")
		if len(artist) < 2 {
			logger.Log.Errorf(MUSIC404, v.id, title[0])
			return
		}
		m.artist = artist[1]
		m.mp3 = fmt.Sprintf(m.url, v.number, m.id)
		album := strings.Split(s.Find("p.album").Text(), ":")
		if len(album) < 2 {
			logger.Log.Errorf(MUSIC404, v.id, title[0])
			return
		}
		m.album = album[1]
		m.cover, isExist = s.Find("a.btn-action-share").Attr("data-img")
		if !isExist {
			logger.Log.Errorf(MUSIC404, v.id, title[0])
			return
		}
		m.Printer()
		ifp.WriteString(fmt.Sprintf("%s\n", m.title))
		if err != nil {
			logger.Log.Errorf(MUSIC404, v.id, err.Error())
		}
		logger.Log.Info("Writing intro complete")
		res, err = v.downloader.Start("GET", m.cover)
		logger.Log.Info("Downloading mp3 cover...")
		m.coverPath = path.Join(filePath, fmt.Sprintf("%s.jpg", m.title))
		mcf, err := os.Create(m.coverPath)
		if err != nil {
			logger.Log.Errorf(DOWNLOADMP3FAIL, v.id, m.id, err.Error())
			return
		}
		_, err = io.Copy(mcf, res.Body)
		if err != nil {
			logger.Log.Errorf(CREATEMP3FAIL, v.id, m.id, err.Error())
		}
		logger.Log.Info("Downloading mp3 cover complete")

		res, err = v.downloader.Start("GET", m.mp3)
		logger.Log.Info("Downloading mp3 ...")
		m.mp3Path = path.Join(filePath, fmt.Sprintf("%s.mp3", m.title))
		mf, err := os.Create(m.mp3Path)
		if err != nil {
			logger.Log.Errorf(DOWNLOADMP3FAIL, v.id, m.id, err.Error())
			return
		}
		_, err = io.Copy(mf, res.Body)
		if err != nil {
			logger.Log.Errorf(CREATEMP3FAIL, v.id, m.id, err.Error())
		}
		logger.Log.Info("Downloading mp3 complete")
	})
}

func (v *Vol)Printer() {
	logger.Log.Infof("Vol Id    : %s", v.id)
	logger.Log.Infof("Vol Url   : %s", v.url)
	logger.Log.Infof("Vol Number: %s", v.number)
	logger.Log.Infof("Vol Title : %s", v.title)
	logger.Log.Infof("Vol Intro : %s", v.intro)
	logger.Log.Infof("Vol Cover : %s", v.cover)
}

func NewMusic() *Music {
	return &Music{
		url: 	"http://mp3-cdn2.luoo.net/low/luoo/radio%s/%s.mp3",
	}
}

func (m *Music)Printer() {
	logger.Log.Info("--------------------------------")
	logger.Log.Infof("Music Id    : %s", m.id)
	logger.Log.Infof("Music Map3  : %s", m.mp3)
	logger.Log.Infof("Music Title : %s", m.title)
	logger.Log.Infof("Music Artist: %s", m.artist)
	logger.Log.Infof("Music album : %s", m.album)
	logger.Log.Infof("Music Cover : %s", m.cover)
}

func (m *Music)SetId(id string) {
	m.id = id
}

func (m *Music)SetUrl(url string) {
	m.url = url
}

func (m *Music)SetDownloader(d *engine.HttpEngine) {
	m.downloader = d
}

func main() {
	luo := NewLuoo(100, 100)
	luo.SetDownloader()
	luo.Download()
}
