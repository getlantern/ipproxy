module github.com/getlantern/ipproxy

go 1.12

require (
	github.com/aristanetworks/goarista v0.0.0-20190429220743-799535f6f364 // indirect
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7
	github.com/getlantern/eventual v0.0.0-20180125201821-84b02499361b
	github.com/getlantern/fdcount v0.0.0-20170105153814-6a6cb5839bc5
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7
	github.com/getlantern/grtrack v0.0.0-20160824195228-cbf67d3fa0fd // indirect
	github.com/getlantern/mtime v0.0.0-20170117193331-ba114e4a82b0 // indirect
	github.com/google/netstack v0.0.0-20191116005144-95bf25ab4723
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/stretchr/testify v1.3.0
)

replace github.com/google/netstack => github.com/getlantern/netstack v0.0.0-20200917193938-4067a7f942d1
