package tun

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const fpath = "/dev/net/tun"

// Config holds configuration for a Device
type Config struct {
	Name, Addr, Route string
}

// Device represents a TUN device
type Device interface {
	io.ReadWriteCloser
}

// New creates-, and configures a TUN device
// and returns it.
func New(conf Config) (Device, error) {
	fd, err := unix.Open(fpath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s err: %w", fpath, err)
	}
	if err := ioctl(conf.Name, fd); err != nil {
		return nil, fmt.Errorf("ioctl err: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set nonBlock op err: %w", err)
	}
	f := os.NewFile(uintptr(fd), fpath)
	return f, configure(conf)
}

// ioctl binds an fd to a TUN device.
func ioctl(ifname string, fd int) error {
	req, err := unix.NewIfreq(ifname)
	if err != nil {
		return err
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	return unix.IoctlIfreq(fd, unix.TUNSETIFF, req)
}

// configure brings up a TUN device defined in Config.
//
// A route and primary addr is assigned (if set).
func configure(conf Config) error {
	link, err := netlink.LinkByName(conf.Name)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}
	if conf.Addr != "" {
		addr, err := netlink.ParseAddr(conf.Addr)
		if err != nil {
			return err
		}
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			return err
		}
	}
	if conf.Route == "" {
		return nil
	}
	// check existing route before creating a new one
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.String() == conf.Route {
			log.Printf("route already set on %+v", r)
			return nil
		}
	}
	_, ipNet, err := net.ParseCIDR(conf.Route)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet,
	}
	return netlink.RouteAdd(route)
}
