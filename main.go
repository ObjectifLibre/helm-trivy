package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"
)

func getChartImages(chart string) (error, []string) {
	images := []string{}
	out, err := exec.Command("helm", "template", chart).Output()
	if err != nil {
		return err, images
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
ScannerLoop:
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "image: ") {
			continue
		}
		image := strings.Split(line, "image: ")[1]
		image = strings.Trim(image, "\"")
		log.Debugf("Found image %v", image)
		for _, v := range images {
			if v == image {
				continue ScannerLoop
			}
		}
		images = append(images, image)
	}
	return nil, images
}

func scanImage(image string, ctx context.Context, cli *client.Client, cacheDir string, json bool) string {
	config := container.Config{
		Image: "aquasec/trivy",
		Cmd:   []string{},
		Tty:   true,
		User:  "1000",
	}
	if json {
		config.Cmd = append(config.Cmd, "-q", "-f", "json", "--cache-dir", "/.cache")
	}
	config.Cmd = append(config.Cmd, image)
	resp, err := cli.ContainerCreate(ctx, &config, &container.HostConfig{
		Binds: []string{"/var/run/docker.sock:/var/run/docker.sock",
			cacheDir + ":/.cache"},
	}, nil, "")
	if err != nil {
		log.Fatalf("Could not create trivy container: %v", err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		log.Fatalf("Could not start trivy container: %v", err)
	}
	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("Error while waiting for container: %v", err)
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true, ShowStderr: false})
	if err != nil {
		log.Fatalf("Cannot get container logs: %v", err)
	}
	outputContent, _ := ioutil.ReadAll(out)
	return string(outputContent)
}

func scanChart(chart string, json bool, ctx context.Context, cli *client.Client, cacheDir string) {
	log.Infof("Scanning chart %s", chart)
	jsonOutput := ""
	if err, images := getChartImages(chart); err != nil {
		log.Fatalf("Could not find images for chart %v: %v\nDid you run 'help update ?'", chart, err)
	} else {
		log.Debugf("Found images for chart %v: %v", chart, images)
		for _, image := range images {
			log.Debugf("Scanning image %v", image)
			output := scanImage(image, ctx, cli, cacheDir, json)
			if json {
				jsonOutput += output
			} else {
				fmt.Println(output)
			}
		}
	}
	if json {
		fmt.Println(strings.ReplaceAll(jsonOutput, "][", ","))
	}
}

func main() {
	var jsonOutput bool
	var debug bool
	var chart string

	flag.BoolVar(&jsonOutput, "json", false, "Enable JSON output")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")

	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	for _, v := range os.Args[1:] {
		if strings.HasPrefix(v, "-") {
			continue
		}
		chart = v
		break
	}

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Could not get docker client: %v", err)
	}

	cacheDir, err := ioutil.TempDir("", "helm-trivy")
	if err != nil {
		log.Fatalf("Could not create cache dir: %v", err)
	}
	log.Debugf("Using %v as cache directory for vuln db", cacheDir)

	defer os.RemoveAll(cacheDir)

	scanChart(chart, jsonOutput, ctx, cli, cacheDir)
}
