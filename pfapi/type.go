package pfapi

import (
	"strconv"
	"strings"
)

type StringOrInt string

func (d *StringOrInt) UnmarshalJSON(b []byte) error {
	str := strings.Replace(string(b), "\"", "", -1)
	*d = StringOrInt(str)
	return nil
}
func (d *StringOrInt) ToString() string {
	return string(*d)
}
func (d *StringOrInt) ToInt() int {
	i, _ := strconv.Atoi(d.ToString())

	return i
}
