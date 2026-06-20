package geoip

import (
	"errors"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var ErrNotLoaded = errors.New("geoip database not loaded")

type CityResult struct {
	CountryCode string
	CountryName string
	CityName    string
	TimeZone    string
	Latitude    float64
	Longitude   float64
}

type Manager struct {
	dbPath string

	mu     sync.RWMutex
	reader *geoip2.Reader
}

func NewManager(dbPath string) *Manager {
	return &Manager{dbPath: dbPath}
}

func (m *Manager) Load() error {
	r, err := geoip2.Open(m.dbPath)
	if err != nil {
		return err
	}

	m.mu.Lock()
	old := m.reader
	m.reader = r
	m.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (m *Manager) Loaded() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reader != nil
}

func (m *Manager) Lookup(ip string) (CityResult, error) {
	if m == nil {
		return CityResult{}, ErrNotLoaded
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return CityResult{}, errors.New("invalid IP address")
	}

	m.mu.RLock()
	r := m.reader
	m.mu.RUnlock()
	if r == nil {
		return CityResult{}, ErrNotLoaded
	}

	rec, err := r.City(parsed)
	if err != nil {
		return CityResult{}, err
	}
	out := CityResult{
		CountryCode: rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		CityName:    rec.City.Names["en"],
		TimeZone:    rec.Location.TimeZone,
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
	}
	if out.CountryCode == "" {
		out.CountryCode = rec.RegisteredCountry.IsoCode
		out.CountryName = rec.RegisteredCountry.Names["en"]
	}
	return out, nil
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		_ = m.reader.Close()
		m.reader = nil
	}
}
