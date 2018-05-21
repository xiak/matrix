package base

import (
	"testing"
	"time"
	"os"
	"io"
)

func TestEarthBase_DispatchTask(t *testing.T) {



	equip, err := NewEquipHttp("http://mp3-cdn2.luoo.net/low/luoo/radio726/01.mp3", 5*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to equip HTTP: %v", err)
	}
	neb := NewNeb()
	resp, err := neb.Transport(equip)
	if err != nil {
		t.Fatalf("Failed to transport: %v", err)
	}

	f, err := os.Create("test.mp3")
	io.Copy(f, resp.Body)
}
