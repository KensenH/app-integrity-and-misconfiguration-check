package main

import (
	"encoding/json"
	"fmt"

	"github.com/r3labs/diff/v3"
)

func main() {
	jsonstr := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"ubuntu","labels":{"app":"ubuntu"}},"spec":{"containers":[{"image":"ubuntu","command":["sleep","604800"],"imagePullPolicy":"IfNotPresent","name":"ubuntu"}],"restartPolicy":"Always"}}`
	jsonstr2 := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"ubuntu","labels":{"app":"ubuntu"}},"spec":{"containers":[{"image":"ubuntu","command":["sleep","604800"],"imagePullPolicy":"IfNotPresent","name":"ubuntu"}],"restartPolicy":"Always"}}`
	from := make(map[string]interface{})
	to := make(map[string]interface{})

	err := json.Unmarshal([]byte(jsonstr), &from)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal([]byte(jsonstr2), &to)
	if err != nil {
		panic(err)
	}

	fmt.Println(from["apiVersion"])

	changelog, _ := diff.Diff(to, from)
	fmt.Println(changelog)

}
