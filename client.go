package fastdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libdns/libdns"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Token struct {
	Expire time.Time `json:"expire"`
	Token  string    `json:"token"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Domain struct {
	Id        int       `json:"id"`
	Name      string    `json:"name"`
	OwnerId   int       `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Record struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Serial   int    `json:"serial"`
	Refresh  int    `json:"refresh"`
	Retry    int    `json:"retry"`
	Expire   int    `json:"expire"`
	Ttl      int    `json:"ttl"`
	Tag      string `json:"tag"`
	Flag     int    `json:"flag"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
}

type RecordForm struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Ttl      int    `json:"ttl"`
	Tag      string `json:"tag"`
	Flag     int    `json:"flag"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
}

func (p *Provider) doAuth(ctx context.Context) (string, error) {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = "/login_token"
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authenticate", p.APIToken)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return "", errors.New(string(bodyBytes[:]))
		}
		return "", errors.New(_error.Message)
	}
	var token Token
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		return "", err
	}
	p.token = token
	return token.Token, nil
}

func (p *Provider) getDomainByZone(ctx context.Context, zone string) (Domain, error) {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = fmt.Sprintf("/api/domains/%s/name", zone)
	if err != nil {
		return Domain{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)
	if err != nil {
		return Domain{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Domain{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Domain{}, err
	}
	if resp.StatusCode != 200 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return Domain{}, errors.New(string(bodyBytes[:]))
		}
		return Domain{}, errors.New(_error.Message)
	}
	var domain Domain
	err = json.Unmarshal(bodyBytes, &domain)
	if err != nil {
		return Domain{}, err
	}
	return domain, nil
}

func (p *Provider) getRecords(ctx context.Context, domainId int) ([]Record, error) {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = fmt.Sprintf("/api/domains/%d/records", domainId)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return nil, errors.New(string(bodyBytes[:]))
		}
		return nil, errors.New(_error.Message)
	}
	var records []Record
	err = json.Unmarshal(bodyBytes, &records)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (p *Provider) createRecord(ctx context.Context, domainId int, record RecordForm) (Record, error) {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = fmt.Sprintf("/api/domains/%d/records", domainId)
	if err != nil {
		return Record{}, err
	}
	jsonValue, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)
	if err != nil {
		return Record{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Record{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Record{}, err
	}
	if resp.StatusCode != 201 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return Record{}, errors.New(string(bodyBytes[:]))
		}
		return Record{}, errors.New(_error.Message)
	}
	var retRecord Record
	err = json.Unmarshal(bodyBytes, &retRecord)
	if err != nil {
		return Record{}, err
	}
	return retRecord, nil
}

func (p *Provider) deleteRecord(ctx context.Context, domainId int, recordId string) error {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = fmt.Sprintf("/api/domains/%d/records/%s", domainId, recordId)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "DELETE", u.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return errors.New(string(bodyBytes[:]))
		}
		return errors.New(_error.Message)
	}
	return nil
}

func (p *Provider) updateRecord(ctx context.Context, domainId int, record Record) (Record, error) {
	if p.APIUrl == "" {
		p.APIUrl = DefaultUrl
	}
	u, err := url.Parse(p.APIUrl)
	u.Path = fmt.Sprintf("/api/domains/%d/records/%s", domainId, record.Id)
	if err != nil {
		return Record{}, err
	}
	jsonValue, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", u.String(), bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token.Token)
	if err != nil {
		return Record{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Record{}, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Record{}, err
	}
	if resp.StatusCode != 200 {
		var _error Error
		err = json.Unmarshal(bodyBytes, &_error)
		if err != nil {
			return Record{}, errors.New(string(bodyBytes[:]))
		}
		return Record{}, errors.New(_error.Message)
	}
	var retRecord Record
	err = json.Unmarshal(bodyBytes, &retRecord)
	if err != nil {
		return Record{}, err
	}
	return retRecord, nil
}

func (p *Provider) getDNSEntries(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, err := p.doAuth(ctx)
	if err != nil {
		return nil, err
	}
	domain, err := p.getDomainByZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	entries, err := p.getRecords(ctx, domain.Id)
	if err != nil {
		return nil, err
	}
	var records []libdns.Record
	for _, entry := range entries {
		record := libdns.Record{
			ID:       entry.Id,
			Type:     entry.Type,
			Name:     entry.Name,
			Value:    entry.Content,
			TTL:      time.Duration(entry.Ttl) * time.Second,
			Priority: entry.Priority,
		}
		records = append(records, record)
	}

	return records, nil
}

func (p *Provider) addDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, err := p.doAuth(ctx)
	if err != nil {
		return libdns.Record{}, err
	}
	domain, err := p.getDomainByZone(ctx, zone)
	if err != nil {
		return libdns.Record{}, err
	}
	entry, err := p.createRecord(ctx, domain.Id, RecordForm{
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Value,
		Ttl:      int(record.TTL.Seconds()),
		Priority: record.Priority,
	})
	if err != nil {
		return libdns.Record{}, err
	}
	return libdns.Record{
		ID:       entry.Id,
		Type:     entry.Type,
		Name:     entry.Name,
		Value:    entry.Content,
		TTL:      time.Duration(entry.Ttl) * time.Second,
		Priority: entry.Priority,
	}, nil
}

func (p *Provider) removeDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, err := p.doAuth(ctx)
	if err != nil {
		return record, err
	}
	domain, err := p.getDomainByZone(ctx, zone)
	if err != nil {
		return record, err
	}
	err = p.deleteRecord(ctx, domain.Id, record.ID)
	if err != nil {
		return record, err
	}
	return record, nil
}

func (p *Provider) updateDNSEntry(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	_, err := p.doAuth(ctx)
	if err != nil {
		return libdns.Record{}, err
	}
	domain, err := p.getDomainByZone(ctx, zone)
	if err != nil {
		return libdns.Record{}, err
	}
	entry, err := p.updateRecord(ctx, domain.Id, Record{
		Id:       record.ID,
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Value,
		Ttl:      int(record.TTL.Seconds()),
		Priority: record.Priority,
	})
	if err != nil {
		return libdns.Record{}, err
	}
	return libdns.Record{
		ID:       entry.Id,
		Type:     entry.Type,
		Name:     entry.Name,
		Value:    entry.Content,
		TTL:      time.Duration(entry.Ttl) * time.Second,
		Priority: entry.Priority,
	}, nil
}
