/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef WIN32
#ifndef OPENVPN_WIN32_H
#define OPENVPN_WIN32_H

#include "mtu.h"
#if _WIN32_WINNT >= 0x0600
#include <initguid.h>
#include <fwpmtypes.h>
#endif

/* location of executables */
#define SYS_PATH_ENV_VAR_NAME "SystemRoot"  /* environmental variable name that normally contains the system path */
#define NETSH_PATH_SUFFIX     "\\system32\\netsh.exe"
#define WIN_ROUTE_PATH_SUFFIX "\\system32\\route.exe"
#define WIN_IPCONFIG_PATH_SUFFIX "\\system32\\ipconfig.exe"
#define WIN_NET_PATH_SUFFIX "\\system32\\net.exe"

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

/* MSVC headers do not define this macro, so do it here */
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
  (memcmp ((const void*)(a), (const void*)(b), sizeof (struct in6_addr)) == 0)
#endif

void init_win32 (void);
void uninit_win32 (void);

void set_pause_exit_win32 (void);

struct security_attributes
{
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
};

#define HANDLE_DEFINED(h) ((h) != NULL && (h) != INVALID_HANDLE_VALUE)

/*
 * Save old window title.
 */
struct window_title
{
  bool saved;
  char old_window_title [256];
};

struct rw_handle {
  HANDLE read;
  HANDLE write;
};

/*
 * Event-based notification of incoming TCP connections
 */

#define NE32_PERSIST_EVENT (1<<0)
#define NE32_WRITE_EVENT   (1<<1)

static inline bool
defined_net_event_win32 (const struct rw_handle *event)
{
  return event->read != NULL;
}

void init_net_event_win32 (struct rw_handle *event, long network_events, socket_descriptor_t sd, unsigned int flags);
long reset_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd);
void close_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd, unsigned int flags);

/*
 * A stateful variant of the net_event_win32 functions above
 */

struct net_event_win32
{
  struct rw_handle handle;
  socket_descriptor_t sd;
  long event_mask;
};

void net_event_win32_init (struct net_event_win32 *ne);
void net_event_win32_start (struct net_event_win32 *ne, long network_events, socket_descriptor_t sd);
void net_event_win32_reset (struct net_event_win32 *ne);
void net_event_win32_reset_write (struct net_event_win32 *ne);
void net_event_win32_stop (struct net_event_win32 *ne);
void net_event_win32_close (struct net_event_win32 *ne);

static inline bool
net_event_win32_defined (const struct net_event_win32 *ne)
{
  return defined_net_event_win32 (&ne->handle);
}

static inline struct rw_handle *
net_event_win32_get_event (struct net_event_win32 *ne)
{
  return &ne->handle;
}

static inline long
net_event_win32_get_event_mask (const struct net_event_win32 *ne)
{
  return ne->event_mask;
}

static inline void
net_event_win32_clear_selected_events (struct net_event_win32 *ne, long selected_events)
{
  ne->event_mask &= ~selected_events;
}

/*
 * Signal handling
 */
struct win32_signal {
# define WSO_MODE_UNDEF   0
# define WSO_MODE_SERVICE 1
# define WSO_MODE_CONSOLE 2
  int mode;
  struct rw_handle in;
  DWORD console_mode_save;
  bool console_mode_save_defined;
};

extern struct win32_signal win32_signal; /* static/global */
extern struct window_title window_title; /* static/global */

void win32_signal_clear (struct win32_signal *ws);

/* win32_signal_open startup type */
#define WSO_NOFORCE       0
#define WSO_FORCE_SERVICE 1
#define WSO_FORCE_CONSOLE 2

void win32_signal_open (struct win32_signal *ws,
			int force, /* set to WSO force parm */
			const char *exit_event_name,
			bool exit_event_initial_state);

void win32_signal_close (struct win32_signal *ws);

int win32_signal_get (struct win32_signal *ws);

void win32_pause (struct win32_signal *ws);

bool win32_service_interrupt (struct win32_signal *ws);

/*
 * Set the text on the window title bar
 */

void window_title_clear (struct window_title *wt);
void window_title_save (struct window_title *wt);
void window_title_restore (const struct window_title *wt);
void window_title_generate (const char *title);

/* 
 * We try to do all Win32 I/O using overlapped
 * (i.e. asynchronous) I/O for a performance win.
 */
struct overlapped_io {
# define IOSTATE_INITIAL          0
# define IOSTATE_QUEUED           1 /* overlapped I/O has been queued */
# define IOSTATE_IMMEDIATE_RETURN 2 /* I/O function returned immediately without queueing */
  int iostate;
  OVERLAPPED overlapped;
  DWORD size;
  DWORD flags;
  int status;
  bool addr_defined;
  union {
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
  };
  int addrlen;
  struct buffer buf_init;
  struct buffer buf;
};

void overlapped_io_init (struct overlapped_io *o,
			 const struct frame *frame,
			 BOOL event_state,
			 bool tuntap_buffer);

void overlapped_io_close (struct overlapped_io *o);

static inline bool
overlapped_io_active (struct overlapped_io *o)
{
  return o->iostate == IOSTATE_QUEUED || o->iostate == IOSTATE_IMMEDIATE_RETURN;
}

char *overlapped_io_state_ascii (const struct overlapped_io *o);

/*
 * Use to control access to resources that only one
 * OpenVPN process on a given machine can access at
 * a given time.
 */

struct semaphore
{
  const char *name;
  bool locked;
  HANDLE hand;
};

void semaphore_clear (struct semaphore *s);
void semaphore_open (struct semaphore *s, const char *name);
bool semaphore_lock (struct semaphore *s, int timeout_milliseconds);
void semaphore_release (struct semaphore *s);
void semaphore_close (struct semaphore *s);

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 *
 * It seems you can't run more than one instance
 * of netsh on the same machine at the same time.
 */

extern struct semaphore netcmd_semaphore;
void netcmd_semaphore_init (void);
void netcmd_semaphore_close (void);
void netcmd_semaphore_lock (void);
void netcmd_semaphore_release (void);

/* Set Win32 security attributes structure to allow all access */
bool init_security_attributes_allow_all (struct security_attributes *obj);

/* return true if filename is safe to be used on Windows */
bool win_safe_filename (const char *fn);

/* add constant environmental variables needed by Windows */
struct env_set;

/* get and set the current windows system path */
void set_win_sys_path (const char *newpath, struct env_set *es);
void set_win_sys_path_via_env (struct env_set *es);
char *get_win_sys_path (void);

/* call self in a subprocess */
void fork_to_self (const char *cmdline);

/* Find temporary directory */
const char *win_get_tempdir();

/* Convert a string from UTF-8 to UCS-2 */
WCHAR *wide_string (const char* utf8, struct gc_arena *gc);

#if _WIN32_WINNT >= 0x0600
bool win_wfp_block_dns(const NET_IFINDEX index);
bool win_wfp_add_filter (HANDLE engineHandle,
                        const FWPM_FILTER0 *filter,
                        PSECURITY_DESCRIPTOR sd,
                        UINT64 *id);
bool win_wfp_uninit();
bool win_wfp_init();

/* WFP-related define and GUIDs */
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001

// c38d57d1-05a7-4c33-904f-7fbceee60e82
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V4,
   0xc38d57d1,
   0x05a7,
   0x4c33,
   0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
DEFINE_GUID(
   FWPM_LAYER_ALE_AUTH_CONNECT_V6,
   0x4a72393b,
   0x319f,
   0x44bc,
   0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4
);

// d78e1e87-8644-4ea5-9437-d809ecefc971
DEFINE_GUID(
   FWPM_CONDITION_ALE_APP_ID,
   0xd78e1e87,
   0x8644,
   0x4ea5,
   0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71
);

// c35a604d-d22b-4e1a-91b4-68f674ee674b
DEFINE_GUID(
   FWPM_CONDITION_IP_REMOTE_PORT,
   0xc35a604d,
   0xd22b,
   0x4e1a,
   0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b
);

// 4cd62a49-59c3-4969-b7f3-bda5d32890a4
DEFINE_GUID(
   FWPM_CONDITION_IP_LOCAL_INTERFACE,
   0x4cd62a49,
   0x59c3,
   0x4969,
   0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4
);

#endif
#endif
#endif