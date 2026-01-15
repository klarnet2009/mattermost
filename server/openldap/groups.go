// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openldap

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// GetGroup retrieves a single LDAP group by its UID
func (l *LdapImpl) GetGroup(rctx request.CTX, groupUID string) (*model.Group, *model.AppError) {
	if groupUID == "" {
		return nil, model.NewAppError("Ldap.GetGroup", "ent.ldap.get_group.blank_uid.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, model.NewAppError("Ldap.GetGroup", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, model.NewAppError("Ldap.GetGroup", "ent.ldap.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	entry, err := l.searchGroup(conn, groupUID)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			return nil, appErr
		}
		return nil, model.NewAppError("Ldap.GetGroup", "ent.ldap.get_group.search_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return l.ldapEntryToGroup(entry), nil
}

// GetAllGroupsPage retrieves all LDAP groups with pagination
func (l *LdapImpl) GetAllGroupsPage(rctx request.CTX, page int, perPage int, opts model.LdapGroupSearchOpts) ([]*model.Group, int, *model.AppError) {
	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, 0, model.NewAppError("Ldap.GetAllGroupsPage", "ent.ldap.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, 0, model.NewAppError("Ldap.GetAllGroupsPage", "ent.ldap.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	groupFilter := "(objectClass=group)"
	if cfg.GroupFilter != nil && *cfg.GroupFilter != "" {
		groupFilter = *cfg.GroupFilter
	}

	// Add search term filter if provided
	filter := groupFilter
	if opts.Q != "" {
		displayNameAttr := "cn"
		if cfg.GroupDisplayNameAttribute != nil && *cfg.GroupDisplayNameAttribute != "" {
			displayNameAttr = *cfg.GroupDisplayNameAttribute
		}
		escapedQ := ldap.EscapeFilter(opts.Q)
		filter = fmt.Sprintf("(&%s(%s=*%s*))", groupFilter, displayNameAttr, escapedQ)
	}

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   l.getGroupAttributes(),
	}

	result, searchErr := conn.Search(searchRequest)
	if searchErr != nil {
		return nil, 0, model.NewAppError("Ldap.GetAllGroupsPage", "ent.ldap.search_error.app_error", nil, searchErr.Error(), http.StatusInternalServerError)
	}

	totalCount := len(result.Entries)

	// Apply pagination
	start := page * perPage
	end := start + perPage
	if start > totalCount {
		return []*model.Group{}, totalCount, nil
	}
	if end > totalCount {
		end = totalCount
	}

	groups := make([]*model.Group, 0, end-start)
	for i := start; i < end; i++ {
		groups = append(groups, l.ldapEntryToGroup(result.Entries[i]))
	}

	return groups, totalCount, nil
}

// searchGroup searches for a group in LDAP by its UID
func (l *LdapImpl) searchGroup(conn *ldap.Conn, groupUID string) (*ldap.Entry, error) {
	cfg := l.config()

	baseDN := ""
	if cfg.BaseDN != nil {
		baseDN = *cfg.BaseDN
	}

	groupIDAttribute := "entryUUID"
	if cfg.GroupIdAttribute != nil && *cfg.GroupIdAttribute != "" {
		groupIDAttribute = *cfg.GroupIdAttribute
	}

	groupFilter := "(objectClass=group)"
	if cfg.GroupFilter != nil && *cfg.GroupFilter != "" {
		groupFilter = *cfg.GroupFilter
	}

	escapedUID := ldap.EscapeFilter(groupUID)
	filter := fmt.Sprintf("(&%s(%s=%s))", groupFilter, groupIDAttribute, escapedUID)

	searchRequest := &ldap.SearchRequest{
		BaseDN:       baseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       filter,
		Attributes:   l.getGroupAttributes(),
	}

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP group search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, model.NewAppError("Ldap.searchGroup", "ent.ldap.group_not_found.app_error", nil, "", http.StatusNotFound)
	}

	return result.Entries[0], nil
}

// getGroupAttributes returns the list of LDAP attributes to retrieve for groups
func (l *LdapImpl) getGroupAttributes() []string {
	cfg := l.config()

	attrs := []string{"dn"}

	addIfNotEmpty := func(attr *string, defaultVal string) {
		val := defaultVal
		if attr != nil && *attr != "" {
			val = *attr
		}
		attrs = append(attrs, val)
	}

	addIfNotEmpty(cfg.GroupIdAttribute, "entryUUID")
	addIfNotEmpty(cfg.GroupDisplayNameAttribute, "cn")

	return attrs
}

// ldapEntryToGroup converts an LDAP entry to a Mattermost Group
func (l *LdapImpl) ldapEntryToGroup(entry *ldap.Entry) *model.Group {
	cfg := l.config()

	group := &model.Group{
		Source:      model.GroupSourceLdap,
		RemoteId:    model.NewPointer(""),
		Name:        model.NewPointer(""),
		DisplayName: "",
	}

	// Map group ID
	groupIDAttribute := "entryUUID"
	if cfg.GroupIdAttribute != nil && *cfg.GroupIdAttribute != "" {
		groupIDAttribute = *cfg.GroupIdAttribute
	}
	remoteID := entry.GetAttributeValue(groupIDAttribute)
	group.RemoteId = &remoteID

	// Map display name
	displayNameAttribute := "cn"
	if cfg.GroupDisplayNameAttribute != nil && *cfg.GroupDisplayNameAttribute != "" {
		displayNameAttribute = *cfg.GroupDisplayNameAttribute
	}
	group.DisplayName = entry.GetAttributeValue(displayNameAttribute)

	// Generate a name from display name (lowercase, no spaces)
	name := strings.ToLower(strings.ReplaceAll(group.DisplayName, " ", "-"))
	group.Name = &name

	return group
}
