package teams

import (
	"fmt"

	"github.com/keybase/client/go/libkb"
)

func ServiceInit(g *libkb.GlobalContext) {
	g.Log.Warning("@@@ServiceInit")
	NewTeamLoaderAndInstall(g)
	NewFastTeamLoaderAndInstall(g)
	NewAuditorAndInstall(g)
	fmt.Printf("@@@%#v", g.GetTeamBoxAuditor())
	NewBoxAuditorAndInstall(g)
	fmt.Printf("@@@%#v", g.GetTeamBoxAuditor())
	NewImplicitTeamConflictInfoCacheAndInstall(g)
	NewImplicitTeamCacheAndInstall(g)
}
