// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openldap

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// LdapDiagnosticImpl implements einterfaces.LdapDiagnosticInterface
type LdapDiagnosticImpl struct {
	configFunc func() *model.Config
	logger     mlog.LoggerIFace
}

// NewDiagnostic creates a new LdapDiagnosticImpl instance
func NewDiagnostic(configFunc func() *model.Config, logger mlog.LoggerIFace) *LdapDiagnosticImpl {
	return &LdapDiagnosticImpl{
		configFunc: configFunc,
		logger:     logger,
	}
}

// config returns the current LDAP settings
func (d *LdapDiagnosticImpl) config() *model.LdapSettings {
	return &d.configFunc().LdapSettings
}

// RunTest tests the LDAP connection with the current configuration
func (d *LdapDiagnosticImpl) RunTest(rctx request.CTX) *model.AppError {
	return d.RunTestConnection(rctx, *d.config())
}

// GetVendorNameAndVendorVersion returns the LDAP server vendor information
func (d *LdapDiagnosticImpl) GetVendorNameAndVendorVersion(rctx request.CTX) (string, string, error) {
	cfg := d.config()

	conn, err := d.connect(cfg)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	// Query the root DSE for vendor information
	searchRequest := &ldap.SearchRequest{
		BaseDN:       "",
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"vendorName", "vendorVersion", "rootDomainNamingContext", "defaultNamingContext"},
	}

	result, searchErr := conn.Search(searchRequest)
	if searchErr != nil {
		return "", "", fmt.Errorf("failed to query root DSE: %w", searchErr)
	}

	if len(result.Entries) == 0 {
		return "Unknown", "Unknown", nil
	}

	entry := result.Entries[0]
	vendorName := entry.GetAttributeValue("vendorName")
	vendorVersion := entry.GetAttributeValue("vendorVersion")

	// Try to detect Active Directory
	if vendorName == "" {
		if entry.GetAttributeValue("rootDomainNamingContext") != "" {
			vendorName = "Microsoft Active Directory"
		} else if entry.GetAttributeValue("defaultNamingContext") != "" {
			vendorName = "Microsoft Active Directory"
		}
	}

	if vendorName == "" {
		vendorName = "Unknown LDAP Server"
	}
	if vendorVersion == "" {
		vendorVersion = "Unknown"
	}

	return vendorName, vendorVersion, nil
}

// RunTestConnection tests the LDAP connection with the provided settings
func (d *LdapDiagnosticImpl) RunTestConnection(rctx request.CTX, settings model.LdapSettings) *model.AppError {
	if settings.LdapServer == nil || *settings.LdapServer == "" {
		return model.NewAppError("Ldap.RunTestConnection", "ent.ldap.test_connection.no_server.app_error", nil, "", http.StatusBadRequest)
	}

	conn, err := d.connect(&settings)
	if err != nil {
		rctx.Logger().Error("LDAP connection test failed", mlog.Err(err))
		return model.NewAppError("Ldap.RunTestConnection", "ent.ldap.test_connection.connection_failed.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer conn.Close()

	// Test admin bind
	bindUsername := ""
	bindPassword := ""
	if settings.BindUsername != nil {
		bindUsername = *settings.BindUsername
	}
	if settings.BindPassword != nil {
		bindPassword = *settings.BindPassword
	}

	if bindUsername != "" {
		if err := conn.Bind(bindUsername, bindPassword); err != nil {
			rctx.Logger().Error("LDAP admin bind failed", mlog.Err(err))
			return model.NewAppError("Ldap.RunTestConnection", "ent.ldap.test_connection.bind_failed.app_error", nil, err.Error(), http.StatusUnauthorized)
		}
	}

	rctx.Logger().Info("LDAP connection test successful")
	return nil
}

// RunTestDiagnostics runs diagnostic tests on LDAP configuration
func (d *LdapDiagnosticImpl) RunTestDiagnostics(rctx request.CTX, testType model.LdapDiagnosticTestType, settings model.LdapSettings) ([]model.LdapDiagnosticResult, *model.AppError) {
	results := []model.LdapDiagnosticResult{}

	conn, err := d.connect(&settings)
	if err != nil {
		return nil, model.NewAppError("Ldap.RunTestDiagnostics", "ent.ldap.diagnostics.connection_failed.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer conn.Close()

	// Bind with admin credentials
	if settings.BindUsername != nil && *settings.BindUsername != "" {
		if err := conn.Bind(*settings.BindUsername, *settings.BindPassword); err != nil {
			return nil, model.NewAppError("Ldap.RunTestDiagnostics", "ent.ldap.diagnostics.bind_failed.app_error", nil, err.Error(), http.StatusUnauthorized)
		}
	}

	switch testType {
	case model.LdapDiagnosticTestTypeFilters:
		results = d.testFilters(conn, &settings)
	case model.LdapDiagnosticTestTypeAttributes:
		results = d.testUserAttributes(conn, &settings)
	case model.LdapDiagnosticTestTypeGroupAttributes:
		results = d.testGroupAttributes(conn, &settings)
	default:
		return nil, model.NewAppError("Ldap.RunTestDiagnostics", "ent.ldap.diagnostics.invalid_test_type.app_error", nil, "", http.StatusBadRequest)
	}

	return results, nil
}

// connect creates a connection to LDAP with the provided settings
func (d *LdapDiagnosticImpl) connect(settings *model.LdapSettings) (*ldap.Conn, error) {
	server := *settings.LdapServer
	port := 389
	if settings.LdapPort != nil {
		port = *settings.LdapPort
	}

	address := fmt.Sprintf("%s:%d", server, port)

	connectionSecurity := ""
	if settings.ConnectionSecurity != nil {
		connectionSecurity = *settings.ConnectionSecurity
	}

	switch strings.ToUpper(connectionSecurity) {
	case "TLS":
		return ldap.DialTLS("tcp", address, nil)
	case "STARTTLS":
		conn, err := ldap.Dial("tcp", address)
		if err != nil {
			return nil, err
		}
		if err := conn.StartTLS(nil); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	default:
		return ldap.Dial("tcp", address)
	}
}

// testFilters tests the user and group filters
func (d *LdapDiagnosticImpl) testFilters(conn *ldap.Conn, settings *model.LdapSettings) []model.LdapDiagnosticResult {
	results := []model.LdapDiagnosticResult{}

	baseDN := ""
	if settings.BaseDN != nil {
		baseDN = *settings.BaseDN
	}

	// Test user filter
	userFilter := "(objectClass=user)"
	if settings.UserFilter != nil && *settings.UserFilter != "" {
		userFilter = *settings.UserFilter
	}

	userResult := model.LdapDiagnosticResult{
		TestName:  "User Filter",
		TestValue: userFilter,
	}

	searchRequest := &ldap.SearchRequest{
		BaseDN:     baseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     userFilter,
		Attributes: []string{"dn"},
		SizeLimit:  100,
	}

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		userResult.Error = err.Error()
	} else {
		userResult.TotalCount = len(searchResult.Entries)
		userResult.Message = fmt.Sprintf("Found %d users", len(searchResult.Entries))

		// Add sample entries
		for i := 0; i < len(searchResult.Entries) && i < 5; i++ {
			userResult.SampleResults = append(userResult.SampleResults, model.LdapSampleEntry{
				DN: searchResult.Entries[i].DN,
			})
		}
	}
	results = append(results, userResult)

	// Test group filter if configured
	if settings.GroupFilter != nil && *settings.GroupFilter != "" {
		groupBaseDN := baseDN

		groupResult := model.LdapDiagnosticResult{
			TestName:  "Group Filter",
			TestValue: *settings.GroupFilter,
		}

		searchRequest := &ldap.SearchRequest{
			BaseDN:     groupBaseDN,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     *settings.GroupFilter,
			Attributes: []string{"dn"},
			SizeLimit:  100,
		}

		searchResult, err := conn.Search(searchRequest)
		if err != nil {
			groupResult.Error = err.Error()
		} else {
			groupResult.TotalCount = len(searchResult.Entries)
			groupResult.Message = fmt.Sprintf("Found %d groups", len(searchResult.Entries))
		}
		results = append(results, groupResult)
	}

	return results
}

// testUserAttributes tests user attribute mappings
func (d *LdapDiagnosticImpl) testUserAttributes(conn *ldap.Conn, settings *model.LdapSettings) []model.LdapDiagnosticResult {
	results := []model.LdapDiagnosticResult{}

	baseDN := ""
	if settings.BaseDN != nil {
		baseDN = *settings.BaseDN
	}

	userFilter := "(objectClass=user)"
	if settings.UserFilter != nil && *settings.UserFilter != "" {
		userFilter = *settings.UserFilter
	}

	// Attributes to test
	attributesToTest := map[string]*string{
		"ID Attribute":       settings.IdAttribute,
		"Username Attribute": settings.UsernameAttribute,
		"Email Attribute":    settings.EmailAttribute,
		"First Name":         settings.FirstNameAttribute,
		"Last Name":          settings.LastNameAttribute,
		"Nickname":           settings.NicknameAttribute,
		"Position":           settings.PositionAttribute,
	}

	for testName, attrPtr := range attributesToTest {
		if attrPtr == nil || *attrPtr == "" {
			continue
		}

		attr := *attrPtr
		result := model.LdapDiagnosticResult{
			TestName:  testName,
			TestValue: attr,
		}

		searchRequest := &ldap.SearchRequest{
			BaseDN:     baseDN,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     userFilter,
			Attributes: []string{attr},
			SizeLimit:  100,
		}

		searchResult, err := conn.Search(searchRequest)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.TotalCount = len(searchResult.Entries)
			entriesWithValue := 0
			for _, entry := range searchResult.Entries {
				if entry.GetAttributeValue(attr) != "" {
					entriesWithValue++
				}
			}
			result.EntriesWithValue = entriesWithValue
			result.Message = fmt.Sprintf("%d/%d entries have this attribute", entriesWithValue, len(searchResult.Entries))
		}

		results = append(results, result)
	}

	return results
}

// testGroupAttributes tests group attribute mappings
func (d *LdapDiagnosticImpl) testGroupAttributes(conn *ldap.Conn, settings *model.LdapSettings) []model.LdapDiagnosticResult {
	results := []model.LdapDiagnosticResult{}

	groupBaseDN := ""
	if settings.BaseDN != nil {
		groupBaseDN = *settings.BaseDN
	}

	groupFilter := "(objectClass=group)"
	if settings.GroupFilter != nil && *settings.GroupFilter != "" {
		groupFilter = *settings.GroupFilter
	}

	attributesToTest := map[string]*string{
		"Group ID Attribute":           settings.GroupIdAttribute,
		"Group Display Name Attribute": settings.GroupDisplayNameAttribute,
	}

	for testName, attrPtr := range attributesToTest {
		if attrPtr == nil || *attrPtr == "" {
			continue
		}

		attr := *attrPtr
		result := model.LdapDiagnosticResult{
			TestName:  testName,
			TestValue: attr,
		}

		searchRequest := &ldap.SearchRequest{
			BaseDN:     groupBaseDN,
			Scope:      ldap.ScopeWholeSubtree,
			Filter:     groupFilter,
			Attributes: []string{attr},
			SizeLimit:  100,
		}

		searchResult, err := conn.Search(searchRequest)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.TotalCount = len(searchResult.Entries)
			entriesWithValue := 0
			for _, entry := range searchResult.Entries {
				if entry.GetAttributeValue(attr) != "" {
					entriesWithValue++
				}
			}
			result.EntriesWithValue = entriesWithValue
			result.Message = fmt.Sprintf("%d/%d groups have this attribute", entriesWithValue, len(searchResult.Entries))
		}

		results = append(results, result)
	}

	return results
}
