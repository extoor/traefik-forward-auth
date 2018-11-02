package config

import "strings"

type Data struct {
	values map[string]bool
	any    bool
}

func (d *Data) Parse(raw string) {
	if raw == "" {
		return
	}

	if raw == "*" {
		d.any = true
		return
	}

	v := strings.Split(raw, ",")

	d.values = make(map[string]bool, len(v))

	for _, value := range v {
		d.values[value] = true
	}

	return
}

func (d *Data) Empty() bool {
	return !d.any && d.values == nil
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

func NewData(raw string) *Data {
	data := new(Data)
	data.Parse(raw)
	return data
}
