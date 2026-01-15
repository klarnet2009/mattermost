// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package openldap

import (
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/v8/channels/app"
	"github.com/mattermost/mattermost/server/v8/channels/app/platform"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

func init() {
	// Register LDAP implementation
	app.RegisterLdapInterface(NewLdapInterface)

	// Register LDAP Diagnostic implementation
	platform.RegisterLdapDiagnosticInterface(NewLdapDiagnosticInterface)
}

// NewLdapInterface creates a new LdapInterface implementation
func NewLdapInterface(a *app.App) einterfaces.LdapInterface {
	return New(
		func() *model.Config { return a.Srv().Config() },
		func() *model.License { return a.Srv().License() },
		func() interface{} { return a.Srv().Store() },
		a.Log(),
	)
}

// NewLdapDiagnosticInterface creates a new LdapDiagnosticInterface implementation
func NewLdapDiagnosticInterface(ps *platform.PlatformService) einterfaces.LdapDiagnosticInterface {
	return NewDiagnostic(
		func() *model.Config { return ps.Config() },
		ps.Log(),
	)
}
