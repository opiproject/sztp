package secureAgent

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

//Auxiliar function to get lines from file matching with the substr
func linesInFileContains(file string, substr string) string {
	f, _ := os.Open(file)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

func extractURLfromLine(line, regex string) string {
	re := regexp.MustCompile(regex)
	return re.FindAllString(line, -1)[1]
}
