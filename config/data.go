package config

import "strings"

type Data struct {
	values map[string]bool
	any    bool
}

func (d *Data) Exists(value string) bool {
	if d.any {
		return true
	}

	if d.values == nil {
		return false
	}

	return d.values[value]
}

func NewData(raw string) (data *Data) {
	data = new(Data)

	if raw == "" {
		return
	}

	if raw == "*" {
		data.any = true
		return
	}

	v := strings.Split(raw, ",")

	data.values = make(map[string]bool, len(v))

	for _, value := range v {
		data.values[value] = true
	}

	return
}
