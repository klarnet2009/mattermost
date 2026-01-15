// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openldap

import (
	"net/http"

	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// GetUser retrieves a user from LDAP by their ID
func (l *LdapImpl) GetUser(rctx request.CTX, id string) (*model.User, *model.AppError) {
	if id == "" {
		return nil, model.NewAppError("Ldap.GetUser", "ent.ldap.get_user.blank_id.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, model.NewAppError("Ldap.GetUser", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		rctx.Logger().Error("Failed to connect to LDAP", "error", err.Error())
		return nil, model.NewAppError("Ldap.GetUser", "ent.ldap.get_user.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	entry, err := l.searchUser(conn, id)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			return nil, appErr
		}
		return nil, model.NewAppError("Ldap.GetUser", "ent.ldap.get_user.search_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return l.ldapUserToMattermostUser(entry), nil
}

// GetLDAPUserForMMUser retrieves the LDAP user corresponding to a Mattermost user
func (l *LdapImpl) GetLDAPUserForMMUser(rctx request.CTX, mmUser *model.User) (*model.User, string, *model.AppError) {
	if mmUser == nil {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.get_ldap_user.nil_user.app_error", nil, "", http.StatusBadRequest)
	}

	if mmUser.AuthService != model.UserAuthServiceLdap || mmUser.AuthData == nil {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.get_ldap_user.not_ldap_user.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	// Search by ID attribute
	idAttribute := "objectGUID"
	if cfg.IdAttribute != nil && *cfg.IdAttribute != "" {
		idAttribute = *cfg.IdAttribute
	}

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	userFilter := "(objectClass=user)"
	if cfg.UserFilter != nil && *cfg.UserFilter != "" {
		userFilter = *cfg.UserFilter
	}

	escapedID := ldap.EscapeFilter(*mmUser.AuthData)
	filter := "(&" + userFilter + "(" + idAttribute + "=" + escapedID + "))"

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   l.getUserAttributes(),
	}

	result, searchErr := conn.Search(searchRequest)
	if searchErr != nil {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.search_error.app_error", nil, searchErr.Error(), http.StatusInternalServerError)
	}

	if len(result.Entries) == 0 {
		return nil, "", model.NewAppError("Ldap.GetLDAPUserForMMUser", "ent.ldap.user_not_found.app_error", nil, "", http.StatusNotFound)
	}

	entry := result.Entries[0]
	ldapUser := l.ldapUserToMattermostUser(entry)

	return ldapUser, entry.DN, nil
}

// GetUserAttributes retrieves specific attributes for a user
func (l *LdapImpl) GetUserAttributes(rctx request.CTX, id string, attributes []string) (map[string]string, *model.AppError) {
	if id == "" {
		return nil, model.NewAppError("Ldap.GetUserAttributes", "ent.ldap.get_user_attributes.blank_id.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, model.NewAppError("Ldap.GetUserAttributes", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, model.NewAppError("Ldap.GetUserAttributes", "ent.ldap.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       l.getUserFilter(id),
		Attributes:   attributes,
	}

	result, searchErr := conn.Search(searchRequest)
	if searchErr != nil {
		return nil, model.NewAppError("Ldap.GetUserAttributes", "ent.ldap.search_error.app_error", nil, searchErr.Error(), http.StatusInternalServerError)
	}

	if len(result.Entries) == 0 {
		return nil, model.NewAppError("Ldap.GetUserAttributes", "ent.ldap.user_not_found.app_error", nil, "", http.StatusNotFound)
	}

	attrs := make(map[string]string)
	entry := result.Entries[0]
	for _, attr := range attributes {
		attrs[attr] = entry.GetAttributeValue(attr)
	}

	return attrs, nil
}

// GetAllLdapUsers retrieves all users from LDAP
func (l *LdapImpl) GetAllLdapUsers(rctx request.CTX) ([]*model.User, *model.AppError) {
	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, model.NewAppError("Ldap.GetAllLdapUsers", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, model.NewAppError("Ldap.GetAllLdapUsers", "ent.ldap.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	userFilter := "(objectClass=user)"
	if cfg.UserFilter != nil && *cfg.UserFilter != "" {
		userFilter = *cfg.UserFilter
	}

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       userFilter,
		Attributes:   l.getUserAttributes(),
	}

	result, searchErr := conn.Search(searchRequest)
	if searchErr != nil {
		return nil, model.NewAppError("Ldap.GetAllLdapUsers", "ent.ldap.search_error.app_error", nil, searchErr.Error(), http.StatusInternalServerError)
	}

	users := make([]*model.User, 0, len(result.Entries))
	for _, entry := range result.Entries {
		users = append(users, l.ldapUserToMattermostUser(entry))
	}

	rctx.Logger().Debug("Retrieved all LDAP users", "count", len(users))

	return users, nil
}
