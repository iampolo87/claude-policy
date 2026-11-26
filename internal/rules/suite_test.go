package rules

import (
	"github.com/iampolo87/claude-policy/internal/config"
)

// suiteCfg is testdata/suite.policy.toml over the defaults: the profile the
// rule tests were written against, independent of the caller's uid.
func suiteCfg() *config.Config {
	c, err := config.Load("../../testdata/suite.policy.toml")
	if err != nil {
		panic(err)
	}
	return c
}

var noticePostCompact = config.Defaults().Rules.SessionNotice.PostCompact
