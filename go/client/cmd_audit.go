// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build !darwin,!windows

package client

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/keybase/cli"
	"github.com/keybase/client/go/libcmdline"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"golang.org/x/net/context"
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
	Full   bool
	Ls     bool
	Rng    bool
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
			cli.BoolFlag{
				Name:  "full",
				Usage: "Do a full box audit with stored state.",
			},
			cli.BoolFlag{
				Name:  "ls", // TODO RM
				Usage: "ls",
			},
			cli.BoolFlag{
				Name:  "rng", // TODO RM
				Usage: "rng",
			},
		},
		ArgumentHelp: "",
		Action: func(c *cli.Context) {
			cl.ChooseCommand(cmd, "box", c)
		},
	}
}

func (c *CmdAuditBox) ParseArgv(ctx *cli.Context) error {
	c.Ls = ctx.Bool("ls")
	c.Rng = ctx.Bool("rng")
	if c.Ls || c.Rng {
		return nil
	}

	c.TeamID = keybase1.TeamID(ctx.String("team-id"))
	if len(c.TeamID) == 0 {
		return fmt.Errorf("need non-empty team id")
	}
	c.Full = ctx.Bool("full")
	return nil
}

func (c *CmdAuditBox) Run() error {
	boxAuditor := c.G().GetTeamBoxAuditor()
	if boxAuditor == nil {
		return fmt.Errorf("Nil team box auditor. Are you running in standalone mode?")
	}

	cli, err := GetAuditClient(c.G())
	if err != nil {
		return err
	}

	if c.Ls {
		r, err := cli.KnownTeamIDs(context.Background(), 0)
		spew.Dump(r)
		return err
	} else if c.Rng {
		r, err := cli.RandomKnownTeamID(context.Background(), 0)
		spew.Dump(r)
		return err
	}

	if c.Full {
		fmt.Println("FULL")
		err := cli.BoxAuditTeam(context.Background(), keybase1.BoxAuditTeamArg{
			TeamID: keybase1.TeamID(c.TeamID),
		})
		if err != nil {
			return err
		}
	} else {
		fmt.Println("HALF")
		audit, err := cli.AttemptBoxAudit(context.Background(), keybase1.AttemptBoxAuditArg{
			TeamID: keybase1.TeamID(c.TeamID),
		})
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", audit)
	}
	return nil
}

func (c *CmdAuditBox) GetUsage() libkb.Usage {
	return libkb.Usage{
		Config: true,
		API:    true,
	}
}
