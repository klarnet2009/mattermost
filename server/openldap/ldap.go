// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Package openldap provides an open-source implementation of LDAP/AD authentication
// for Mattermost, implementing the einterfaces.LdapInterface.
package openldap

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// LdapImpl implements einterfaces.LdapInterface
type LdapImpl struct {
	configFunc  func() *model.Config
	licenseFunc func() *model.License
	storeFunc   func() interface{} // Will be cast to store.Store
	logger      mlog.LoggerIFace

	connMu sync.Mutex
	conn   *ldap.Conn
}

// New creates a new LdapImpl instance
func New(configFunc func() *model.Config, licenseFunc func() *model.License, storeFunc func() interface{}, logger mlog.LoggerIFace) *LdapImpl {
	return &LdapImpl{
		configFunc:  configFunc,
		licenseFunc: licenseFunc,
		storeFunc:   storeFunc,
		logger:      logger,
	}
}

// config returns the current LDAP settings
func (l *LdapImpl) config() *model.LdapSettings {
	return l.configFunc().LdapSettings
}

// connect establishes a connection to the LDAP server
func (l *LdapImpl) connect() (*ldap.Conn, error) {
	cfg := l.config()

	if cfg.LdapServer == nil || *cfg.LdapServer == "" {
		return nil, fmt.Errorf("LDAP server address is not configured")
	}

	server := *cfg.LdapServer
	port := 389
	if cfg.LdapPort != nil {
		port = *cfg.LdapPort
	}

	address := fmt.Sprintf("%s:%d", server, port)

	var conn *ldap.Conn
	var err error

	// Determine connection security
	connectionSecurity := ""
	if cfg.ConnectionSecurity != nil {
		connectionSecurity = *cfg.ConnectionSecurity
	}

	switch strings.ToUpper(connectionSecurity) {
	case "TLS":
		tlsConfig := &tls.Config{
			ServerName:         server,
			InsecureSkipVerify: cfg.SkipCertificateVerification != nil && *cfg.SkipCertificateVerification,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	case "STARTTLS":
		conn, err = ldap.Dial("tcp", address)
		if err == nil {
			tlsConfig := &tls.Config{
				ServerName:         server,
				InsecureSkipVerify: cfg.SkipCertificateVerification != nil && *cfg.SkipCertificateVerification,
			}
			err = conn.StartTLS(tlsConfig)
		}
	default:
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	return conn, nil
}

// bindAdmin binds with the admin credentials to perform searches
func (l *LdapImpl) bindAdmin(conn *ldap.Conn) error {
	cfg := l.config()

	bindUsername := ""
	bindPassword := ""

	if cfg.BindUsername != nil {
		bindUsername = *cfg.BindUsername
	}
	if cfg.BindPassword != nil {
		bindPassword = *cfg.BindPassword
	}

	if bindUsername == "" {
		// Anonymous bind
		return conn.UnauthenticatedBind("")
	}

	return conn.Bind(bindUsername, bindPassword)
}

// getConnection returns a connected and admin-bound LDAP connection
func (l *LdapImpl) getConnection() (*ldap.Conn, error) {
	l.connMu.Lock()
	defer l.connMu.Unlock()

	// Check if existing connection is still valid
	if l.conn != nil {
		// Try a simple operation to verify connection
		_, err := l.conn.Search(&ldap.SearchRequest{
			BaseDN:     "",
			Scope:      ldap.ScopeBaseObject,
			Filter:     "(objectClass=*)",
			Attributes: []string{"1.1"},
		})
		if err == nil {
			return l.conn, nil
		}
		// Connection is stale, close it
		l.conn.Close()
		l.conn = nil
	}

	// Create new connection
	conn, err := l.connect()
	if err != nil {
		return nil, err
	}

	if err := l.bindAdmin(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind admin: %w", err)
	}

	l.conn = conn
	return conn, nil
}

// Close closes the LDAP connection
func (l *LdapImpl) Close() {
	l.connMu.Lock()
	defer l.connMu.Unlock()

	if l.conn != nil {
		l.conn.Close()
		l.conn = nil
	}
}

// getUserFilter returns the LDAP filter for finding users
func (l *LdapImpl) getUserFilter(loginID string) string {
	cfg := l.config()

	loginIDAttribute := "sAMAccountName"
	if cfg.LoginIdAttribute != nil && *cfg.LoginIdAttribute != "" {
		loginIDAttribute = *cfg.LoginIdAttribute
	}

	userFilter := "(objectClass=user)"
	if cfg.UserFilter != nil && *cfg.UserFilter != "" {
		userFilter = *cfg.UserFilter
	}

	escapedLoginID := ldap.EscapeFilter(loginID)
	return fmt.Sprintf("(&%s(%s=%s))", userFilter, loginIDAttribute, escapedLoginID)
}

// ldapUserToMattermostUser converts an LDAP entry to a Mattermost User
func (l *LdapImpl) ldapUserToMattermostUser(entry *ldap.Entry) *model.User {
	cfg := l.config()

	user := &model.User{
		AuthService: model.UserAuthServiceLdap,
	}

	// Map ID attribute
	idAttribute := "objectGUID"
	if cfg.IdAttribute != nil && *cfg.IdAttribute != "" {
		idAttribute = *cfg.IdAttribute
	}
	if val := entry.GetAttributeValue(idAttribute); val != "" {
		user.AuthData = model.NewPointer(val)
	}

	// Map username
	usernameAttribute := "sAMAccountName"
	if cfg.UsernameAttribute != nil && *cfg.UsernameAttribute != "" {
		usernameAttribute = *cfg.UsernameAttribute
	}
	user.Username = entry.GetAttributeValue(usernameAttribute)

	// Map email
	emailAttribute := "mail"
	if cfg.EmailAttribute != nil && *cfg.EmailAttribute != "" {
		emailAttribute = *cfg.EmailAttribute
	}
	user.Email = entry.GetAttributeValue(emailAttribute)

	// Map first name
	firstNameAttribute := "givenName"
	if cfg.FirstNameAttribute != nil && *cfg.FirstNameAttribute != "" {
		firstNameAttribute = *cfg.FirstNameAttribute
	}
	user.FirstName = entry.GetAttributeValue(firstNameAttribute)

	// Map last name
	lastNameAttribute := "sn"
	if cfg.LastNameAttribute != nil && *cfg.LastNameAttribute != "" {
		lastNameAttribute = *cfg.LastNameAttribute
	}
	user.LastName = entry.GetAttributeValue(lastNameAttribute)

	// Map nickname
	if cfg.NicknameAttribute != nil && *cfg.NicknameAttribute != "" {
		user.Nickname = entry.GetAttributeValue(*cfg.NicknameAttribute)
	}

	// Map position
	if cfg.PositionAttribute != nil && *cfg.PositionAttribute != "" {
		user.Position = entry.GetAttributeValue(*cfg.PositionAttribute)
	}

	return user
}

// searchUser searches for a user in LDAP by their login ID
func (l *LdapImpl) searchUser(conn *ldap.Conn, loginID string) (*ldap.Entry, error) {
	cfg := l.config()

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       l.getUserFilter(loginID),
		Attributes:   l.getUserAttributes(),
	}

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, model.NewAppError("Ldap.searchUser", "ent.ldap.do_login.user_not_registered.app_error", nil, "", http.StatusUnauthorized)
	}

	if len(result.Entries) > 1 {
		return nil, model.NewAppError("Ldap.searchUser", "ent.ldap.do_login.multiple_users.app_error", nil, "", http.StatusUnauthorized)
	}

	return result.Entries[0], nil
}

// getUserAttributes returns the list of LDAP attributes to retrieve
func (l *LdapImpl) getUserAttributes() []string {
	cfg := l.config()

	attrs := []string{"dn"}

	addIfNotEmpty := func(attr *string, defaultVal string) {
		val := defaultVal
		if attr != nil && *attr != "" {
			val = *attr
		}
		attrs = append(attrs, val)
	}

	addIfNotEmpty(cfg.IdAttribute, "objectGUID")
	addIfNotEmpty(cfg.UsernameAttribute, "sAMAccountName")
	addIfNotEmpty(cfg.EmailAttribute, "mail")
	addIfNotEmpty(cfg.FirstNameAttribute, "givenName")
	addIfNotEmpty(cfg.LastNameAttribute, "sn")

	if cfg.NicknameAttribute != nil && *cfg.NicknameAttribute != "" {
		attrs = append(attrs, *cfg.NicknameAttribute)
	}
	if cfg.PositionAttribute != nil && *cfg.PositionAttribute != "" {
		attrs = append(attrs, *cfg.PositionAttribute)
	}
	if cfg.PictureAttribute != nil && *cfg.PictureAttribute != "" {
		attrs = append(attrs, *cfg.PictureAttribute)
	}

	return attrs
}
