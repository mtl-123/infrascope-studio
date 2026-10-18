package migrations

import _ "embed"

//go:embed 001_remote_access.sql
var BaseSQL string

//go:embed 002_people_assets.sql
var PeopleAssetsSQL string

//go:embed 003_asset_scopes.sql
var AssetScopesSQL string

//go:embed 004_organizations.sql
var OrganizationsSQL string

//go:embed 005_asset_imports.sql
var AssetImportsSQL string

//go:embed 006_self_access_requests.sql
var SelfAccessSQL string

//go:embed 007_server_onboarding.sql
var ServerOnboardingSQL string

//go:embed 008_telemetry_agents.sql
var TelemetryAgentsSQL string

var SQL = BaseSQL + "\n" + PeopleAssetsSQL + "\n" + AssetScopesSQL + "\n" + OrganizationsSQL + "\n" + AssetImportsSQL + "\n" + SelfAccessSQL + "\n" + ServerOnboardingSQL + "\n" + TelemetryAgentsSQL
