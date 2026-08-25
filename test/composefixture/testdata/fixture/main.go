package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"
)

const secretPath = "/run/secrets/credential"

type status struct {
	Setting        string `json:"setting"`
	Generation     string `json:"generation"`
	SecretDigest   string `json:"secretDigest"`
	SecretReadOnly bool   `json:"secretReadOnly"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		probe()
		return
	}
	serve()
}

func serve() {
	secret, err := os.ReadFile(secretPath)
	if err != nil || len(secret) > 1024*1024 {
		os.Exit(1)
	}
	digest := sha256.Sum256(secret)
	for index := range secret {
		secret[index] = 0
	}
	file, openErr := os.OpenFile(secretPath, os.O_WRONLY, 0)
	readOnly := openErr != nil
	if file != nil {
		_ = file.Close()
	}
	response := status{
		Setting: os.Getenv("MATRIX_SETTING"), Generation: os.Getenv("MATRIX_GENERATION"),
		SecretDigest: "sha256:" + hex.EncodeToString(digest[:]), SecretReadOnly: readOnly,
	}
	handler := http.NewServeMux()
	handler.HandleFunc("/ready", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	})
	server := &http.Server{
		Addr: ":8080", Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		os.Exit(1)
	}
}

func probe() {
	if len(os.Args) != 6 {
		os.Exit(2)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	var response *http.Response
	for {
		var err error
		response, err = client.Get(os.Args[2])
		if err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			os.Exit(1)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	var observed status
	if err := decoder.Decode(&observed); err != nil {
		os.Exit(1)
	}
	if observed.Setting != os.Args[3] || observed.SecretDigest != os.Args[4] ||
		observed.Generation != os.Args[5] || !observed.SecretReadOnly {
		_ = json.NewEncoder(os.Stdout).Encode(observed)
		os.Exit(1)
	}
}
