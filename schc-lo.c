/* schc-lo.c
 */

#define WS_BUILD_DLL
#include <wireshark.h>
#include <wsutil/plugins.h>
#include <epan/packet.h>
#include <epan/proto.h>

#ifndef VERSION
#define VERSION "0.0.1"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

static int proto_schc_lo;
static dissector_handle_t handle_schc_lo;

static int
dissect_schc_lo(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_protocol_format(tree, proto_schc_lo, tvb, 0, -1, "This is SCHC-Lo plugin version %s, a Wireshark postdissector plugin to parse SCHC-Lo packets", plugin_version);
    return tvb_captured_length(tvb);
}

static void proto_register_schc_lo(void) {
    proto_schc_lo = proto_register_protocol("Wireshark SCHC-Lo Plugin", "SCHC-Lo WS", "schc_lo_ws");
    handle_schc_lo = create_dissector_handle(dissect_schc_lo, proto_schc_lo);
    register_postdissector(handle_schc_lo);
}

static void proto_reg_handoff_schc_lo(void) {
    /* empty */
}

void plugin_register(void) {
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_schc_lo;
    plug.register_handoff = proto_reg_handoff_schc_lo; /* or NULL */
    proto_register_plugin(&plug);
}

uint32_t plugin_describe(void) {
    return WS_PLUGIN_DESC_DISSECTOR;
}
