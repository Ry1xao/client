// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build !darwin,!windows

package client

import (
	"fmt"

	"github.com/keybase/cli"
	"github.com/keybase/client/go/libcmdline"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
)

const backtick = "`"

func NewCmdAudit(cl *libcmdline.CommandLine, g *libkb.GlobalContext) cli.Command {
	commands := []cli.Command{
		NewCmdAuditBox(cl, g),
	}

	return cli.Command{
		Name: "audit",
		// No 'Usage' makes this hidden
		Description: "Perform audits and see the result of previous audits",
		Subcommands: commands,
	}
}

type CmdAuditBox struct {
	libkb.Contextified
	TeamID keybase1.TeamID
}

func NewCmdAuditBox(cl *libcmdline.CommandLine, g *libkb.GlobalContext) cli.Command {
	cmd := &CmdAuditBox{
		Contextified: libkb.NewContextified(g),
	}
	return cli.Command{
		Name: "box",
		Usage: `A team box audit makes sure a team's secrets are actually
	encrypted for the right members in the team, and when members revoke
	devices, the team is rotated accordingly.
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "team-id",
				Usage: "Team ID",
			},
		},
		ArgumentHelp: "",
		Action: func(c *cli.Context) {
			cl.ChooseCommand(cmd, "box", c)
		},
	}
}

func (c *CmdAuditBox) ParseArgv(ctx *cli.Context) error {
	c.TeamID = keybase1.TeamID(ctx.String("team-id"))
	return nil
}

func (c *CmdAuditBox) Run() error {
	fmt.Println("Naw")
	boxAuditor := c.G().GetTeamBoxAuditor()
	fmt.Println("Khoa")
	fmt.Println("@@@%#v", boxAuditor)

	if boxAuditor == nil {
		return fmt.Errorf("Nil team box auditor. Are you running in standalone mode?")
	}

	err := boxAuditor.BoxAuditTeam(libkb.NewMetaContextTODO(c.G()), c.TeamID)
	return err
}

func (c *CmdAuditBox) GetUsage() libkb.Usage {
	return libkb.Usage{
		Config: true,
		API:    true,
	}
}
