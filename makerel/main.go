package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	targets := []struct {
		os   string
		arch []string
	}{
		{"darwin", []string{"386", "amd64"}},
		{"dragonfly", []string{"amd64"}},
		{"freebsd", []string{"386", "amd64", "arm"}},
		{"netbsd", []string{"386", "amd64", "arm"}},
		{"openbsd", []string{"386", "amd64", "arm"}},
		{"plan9", []string{"386", "amd64", "arm"}},
		{"windows", []string{"386", "amd64"}},
		{"linux", []string{"386", "amd64", "arm", "arm64", "ppc64", "ppc64le", "mips", "mipsle", "mips64", "mips64le", "s390x"}},
	}

	for _, t := range targets {
		for _, arch := range t.arch {
			build := exec.Command("go", "build")
			build.Stderr = os.Stderr
			build.Stdout = os.Stdout
			build.Env = append(os.Environ(), "GOOS="+t.os, "GOARCH="+arch)
			if err := build.Run(); err != nil {
				panic(err)
			}
			zip := exec.Command("zip", "")
			zip.Stderr = os.Stderr
			zip.Stdout = os.Stdout
			if t.os == "windows" {
				os.Rename("B593s-22_SSH.exe", "B593s22SSH.exe")
				zip.Args = []string{"-9", fmt.Sprintf("B593s-22_SSH_%s_%s.zip", t.os, arch), "B593s22SSH.exe", "LICENSE", "DONATE", "README.md"}
			} else {
				zip.Args = []string{"-9", fmt.Sprintf("B593s-22_SSH_%s_%s.zip", t.os, arch), "B593s-22_SSH", "LICENSE", "DONATE", "README.md"}
			}
			if err := zip.Run(); err != nil {
				panic(err)
			}
			if t.os == "windows" {
				if err := os.Remove("B593s22SSH.exe"); err != nil {
					panic(err)
				}
				continue
			}
			if err := os.Remove("B593s-22_SSH"); err != nil {
				panic(err)
			}
		}
	}
}
