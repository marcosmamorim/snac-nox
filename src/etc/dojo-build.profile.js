dependencies = {

    layers: [
		{
			name: "../dijit/dijit.js",
			dependencies: [
				"dijit.dijit",
                "dijit.layout.ContentPane",
                "dijit.layout.BorderContainer",
                "dijit.Toolbar",
                "dijit.Menu",
                "dijit.form.Button",
                "dijit.form.Form",
                "dijit.form.FilteringSelect"
			]
		},
        {
            name: "../dojox/grid/DataGrid.js",
			layerDependencies: [
				"../dijit/dijit.js"
			],
            dependencies: [
                "dojox.grid.DataGrid"
            ]
        },
        {
            name: "../dojox/charting/Chart2D.js",
			layerDependencies: [
				"../dijit/dijit.js"
			],
            dependencies: [
                "dojox.charting.Chart2D",
                "dojox.charting.themes.Grasshopper",
                "dojox.charting.action2d.Tooltip"
            ]
        },
        {
            name: "../nox/apps/coreui/coreui/noxcore.js",
            resourceName: "nox.apps.coreui.coreui.noxcore",
            layerDependencies: [ "../dijit/dijit.js" ],
            dependencies: [ "nox.apps.coreui.coreui.noxcore" ],
            copyrightFile: "../../nox/apps/coreui/coreui/nox-js-copyright.txt"
        },
    ],

    prefixes: [
        [ "dijit", "../dijit" ],
        [ "dojox", "../dojox" ],
        [ "nox", "../nox", "../../nox/apps/coreui/coreui/nox-js-copyright.txt" ]
    ]

}
