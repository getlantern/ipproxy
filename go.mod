module github.com/getlantern/ipproxy

go 1.12

require (
	github.com/aristanetworks/goarista v0.0.0-20190429220743-799535f6f364 // indirect
	github.com/getlantern/errors v1.0.1
	github.com/getlantern/eventual v0.0.0-20180125201821-84b02499361b
	github.com/getlantern/fdcount v0.0.0-20170105153814-6a6cb5839bc5
	github.com/getlantern/golog v0.0.0-20200929154820-62107891371a
	github.com/getlantern/grtrack v0.0.0-20160824195228-cbf67d3fa0fd // indirect
	github.com/getlantern/mtime v0.0.0-20170117193331-ba114e4a82b0 // indirect
	github.com/google/netstack v0.0.0-00010101000000-000000000000
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/stretchr/testify v1.3.0
	golang.org/x/sys v0.1.0 // indirect
)

replace github.com/google/netstack => github.com/getlantern/netstack v0.0.0-20200930032729-4d26a3d146e1
