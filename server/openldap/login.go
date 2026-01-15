// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openldap

import (
	"fmt"
	"net/http"

	"github.com/mattermost/ldap"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// DoLogin authenticates a user against LDAP and returns the Mattermost user
func (l *LdapImpl) DoLogin(rctx request.CTX, id string, password string) (*model.User, *model.AppError) {
	if id == "" || password == "" {
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.blank_credentials.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.not_enabled.app_error", nil, "", http.StatusNotImplemented)
	}

	// Get admin connection to search for user
	conn, err := l.getConnection()
	if err != nil {
		rctx.Logger().Error("Failed to connect to LDAP", "error", err.Error())
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	// Search for the user
	entry, err := l.searchUser(conn, id)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			return nil, appErr
		}
		rctx.Logger().Error("Failed to search for user in LDAP", "error", err.Error())
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.search_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	// Verify user password by binding with their credentials
	userDN := entry.DN
	if userDN == "" {
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.user_dn_missing.app_error", nil, "", http.StatusInternalServerError)
	}

	// Create a new connection for user authentication
	authConn, err := l.connect()
	if err != nil {
		rctx.Logger().Error("Failed to create auth connection to LDAP", "error", err.Error())
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.connection_error.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer authConn.Close()

	// Attempt to bind with user credentials
	if err := authConn.Bind(userDN, password); err != nil {
		rctx.Logger().Debug("LDAP authentication failed", "userDN", userDN, "error", err.Error())
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.invalid_credentials.app_error", nil, "", http.StatusUnauthorized)
		}
		return nil, model.NewAppError("Ldap.DoLogin", "ent.ldap.do_login.bind_error.app_error", nil, err.Error(), http.StatusUnauthorized)
	}

	// Convert LDAP entry to Mattermost user
	user := l.ldapUserToMattermostUser(entry)

	rctx.Logger().Debug("LDAP authentication successful", "username", user.Username)

	return user, nil
}

// SwitchToLdap switches a user's authentication to LDAP
func (l *LdapImpl) SwitchToLdap(rctx request.CTX, userID, ldapID, ldapPassword string) *model.AppError {
	if userID == "" || ldapID == "" || ldapPassword == "" {
		return model.NewAppError("Ldap.SwitchToLdap", "ent.ldap.switch_to_ldap.blank_fields.app_error", nil, "", http.StatusBadRequest)
	}

	cfg := l.config()
	if cfg.Enable == nil || !*cfg.Enable {
		return model.NewAppError("Ldap.SwitchToLdap", "ent.ldap.do_login.not_enabled.app_error", nil, "", http.StatusNotImplemented)
	}

	// Verify LDAP credentials first
	ldapUser, appErr := l.DoLogin(rctx, ldapID, ldapPassword)
	if appErr != nil {
		return appErr
	}

	if ldapUser.AuthData == nil || *ldapUser.AuthData == "" {
		return model.NewAppError("Ldap.SwitchToLdap", "ent.ldap.switch_to_ldap.no_auth_data.app_error", nil, "", http.StatusInternalServerError)
	}

	// The actual user update should be done by the caller (app layer)
	// This method just validates that the LDAP credentials are correct
	rctx.Logger().Info("User switching to LDAP authentication", "userID", userID, "ldapID", ldapID)

	return nil
}

// CheckProviderAttributes checks if any user attributes are managed by LDAP
func (l *LdapImpl) CheckProviderAttributes(rctx request.CTX, LS *model.LdapSettings, ouser *model.User, patch *model.UserPatch) string {
	if LS == nil || ouser == nil {
		return ""
	}

	conflictingAttrs := []string{}

	// Check if trying to change LDAP-managed attributes
	if patch.Username != nil && LS.UsernameAttribute != nil && *LS.UsernameAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "username")
	}
	if patch.Email != nil && LS.EmailAttribute != nil && *LS.EmailAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "email")
	}
	if patch.FirstName != nil && LS.FirstNameAttribute != nil && *LS.FirstNameAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "first_name")
	}
	if patch.LastName != nil && LS.LastNameAttribute != nil && *LS.LastNameAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "last_name")
	}
	if patch.Nickname != nil && LS.NicknameAttribute != nil && *LS.NicknameAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "nickname")
	}
	if patch.Position != nil && LS.PositionAttribute != nil && *LS.PositionAttribute != "" {
		conflictingAttrs = append(conflictingAttrs, "position")
	}

	if len(conflictingAttrs) > 0 {
		return fmt.Sprintf("LDAP-managed attributes cannot be changed: %v", conflictingAttrs)
	}

	return ""
}
