/*
 network-macosx.c : Secure Transport support
 
 Copyright (C) 2011 Matt Wright
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <Security/Security.h>

#include "module.h"
#include "network.h"
#include "misc.h"

/* ssl i/o channel object */
typedef struct
{
	GIOChannel pad;
	gint fd;
	GIOChannel *giochan;
  SSLContextRef context;
	unsigned int verify:1;
	const char *hostname;
} GIOSSLChannel;

OSStatus _SSLReadFunction(SSLConnectionRef connection, void *data, size_t *dataLength)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)connection;
  
  size_t len = 0;
  while (len < *dataLength) {
    size_t res = read(channel->fd, ((char*)data)+len, (*dataLength)-len);
    
    if (res == -1) {
      if (errno == EAGAIN) {
        /* eject if we get EAGAIN, means we're in non-block mode */
        *dataLength = len;
        return errSSLWouldBlock;
      }
      g_warning("read returned %d", errno);
      return errSSLInternal;
    }
    len += res;
  }
  *dataLength = len;
  return noErr;
}

OSStatus _SSLWriteFunction(SSLConnectionRef connection, void *data, size_t *dataLength)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)connection;
  
  size_t len = 0;
  while (len < *dataLength) {
    size_t chunk = (*dataLength - len < 4096 ? *dataLength - len : 4096);
    size_t res = write(channel->fd, ((char*)data)+len, chunk);
    
    if (res == -1) {
      if (errno == EAGAIN) {
        *dataLength = len;
        return errSSLWouldBlock;
      }
      g_warning("write returned %d", errno);
      return errSSLInternal;
    }
    len += res;
  }
  *dataLength = len;
  return noErr;
}

static void irssi_ssl_free(GIOChannel *handle)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)handle;
	g_io_channel_unref(channel->giochan);
  SSLDisposeContext(channel->context);
	g_free(channel);
}

static GIOStatus irssi_ssl_read(GIOChannel *handle, gchar *buf, gsize len, gsize *ret, GError **gerr)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)handle;
  size_t processed;
  OSStatus status;
  
  status = SSLRead(channel->context, buf, len, &processed);
  if (status == noErr) {
    *ret = processed;
    return G_IO_STATUS_NORMAL;
  }
  
  *ret = 0;
  
  if (status == errSSLWouldBlock) {
    return G_IO_STATUS_AGAIN;
  }
  
  if (status == errSSLClosedGraceful) {
    return G_IO_STATUS_EOF;
  }
  
  /* TODO: error message */
  return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_write(GIOChannel *handle, const gchar *buf, gsize len, gsize *ret, GError **gerr)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)handle;
  size_t processed;
  OSStatus status;
  
  status = SSLWrite(channel->context, buf, len, &processed);
  if (status == noErr) {
    *ret = processed;
    return G_IO_STATUS_NORMAL;
  }
  
  *ret = 0;
  
  if (status == errSSLWouldBlock) {
    return G_IO_STATUS_AGAIN;
  }

  return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_seek(GIOChannel *handle, gint64 offset, GSeekType type, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
  
	return chan->giochan->funcs->io_seek(handle, offset, type, gerr);
}

static GIOStatus irssi_ssl_close(GIOChannel *handle, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
  
	return chan->giochan->funcs->io_close(handle, gerr);
}

static GSource *irssi_ssl_create_watch(GIOChannel *handle, GIOCondition cond)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
  
	return chan->giochan->funcs->io_create_watch(handle, cond);
}

static GIOStatus irssi_ssl_set_flags(GIOChannel *handle, GIOFlags flags, GError **gerr)
{
  GIOSSLChannel *chan = (GIOSSLChannel *)handle;
  
  return chan->giochan->funcs->io_set_flags(handle, flags, gerr);
}

static GIOFlags irssi_ssl_get_flags(GIOChannel *handle)
{
  GIOSSLChannel *chan = (GIOSSLChannel *)handle;
  
  return chan->giochan->funcs->io_get_flags(handle);
}

static GIOFuncs irssi_ssl_channel_funcs = {
  irssi_ssl_read,
  irssi_ssl_write,
  irssi_ssl_seek,
  irssi_ssl_close,
  irssi_ssl_create_watch,
  irssi_ssl_free,
  irssi_ssl_set_flags,
  irssi_ssl_get_flags
};

static gboolean irssi_ssl_init(void)
{
}

int irssi_ssl_handshake(GIOChannel *handle)
{
  GIOSSLChannel *channel = (GIOSSLChannel*)handle;
  
  /* irssi can, and does, open us non-block and SSLHandshake won't like that */
  OSStatus status;
  int ret;
  
  fd_set write_set;
  FD_ZERO(&write_set);
  FD_SET(channel->fd, &write_set);
  
  while ((ret = select(channel->fd+1, NULL, &write_set, NULL, NULL)) < 1)
  {
    if (ret == 0 || errno == EAGAIN) {
      continue;
    }
    g_warning("select() waiting for socket connect returned %d.", errno);
    return -1;
  }
  
  /* again, we can be non-block and we've been asked to handshake, loop ... */
  while ((status = SSLHandshake(channel->context)) != noErr) {
    if (status != errSSLWouldBlock) {
      g_warning("SSL handshake failed: SSLHandshake returned %d.", status);
      return -1;
    }
  }
  
  /* TODO: verify client certificate */
  return 0;
}

static GIOChannel *irssi_ssl_get_iochannel(GIOChannel *handle, const char *hostname, const char *mycert, const char *mypkey, const char *cafile, const char *capath, gboolean verify)
{
  GIOSSLChannel *channel;
  GIOChannel *gChannel;
  SSLContextRef contextRef;
  int fd;
  
  if (!(fd = g_io_channel_unix_get_fd(handle))) {
    return NULL;
  }
  
  OSStatus status = SSLNewContext(FALSE, &contextRef);
  if (status != noErr) {
    g_error("Failed to create new SSLContextRef, %d.", status);
    return NULL;
  }
  
  status = SSLSetIOFuncs(contextRef, (SSLReadFunc)_SSLReadFunction, (SSLWriteFunc)_SSLWriteFunction);
  if (status != noErr) {
    g_error("Failed to set IOFuncs, %d.", status);
    SSLDisposeContext(contextRef);
    return NULL;
  }
  
  if (!verify) {
    SSLSetAllowsAnyRoot(contextRef, TRUE);
  }
  
  /* TODO: certificate stuff */
  
  channel = g_new0(GIOSSLChannel, 1);
  channel->fd = fd;
  channel->giochan = handle;
  channel->context = contextRef;
  channel->verify = verify;
  channel->hostname = hostname;
  
  gChannel = (GIOChannel*)channel;
  gChannel->funcs = &irssi_ssl_channel_funcs;
  g_io_channel_init(gChannel);
  gChannel->is_readable = gChannel->is_writeable = TRUE;
  gChannel->use_buffer = FALSE;
  
  status = SSLSetConnection(contextRef, (SSLConnectionRef)channel);
  if (status != noErr) {
    g_error("Failed to set SSLConnection, %d.", status);
    SSLDisposeContext(contextRef);
    return NULL;
  }
  
  return gChannel;
}

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, const char* hostname, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify)
{
  GIOChannel *handle, *ssl_handle;
  
  handle = net_connect_ip(ip, port, my_ip);
  if (handle == NULL) {
    return NULL;
  }
  
  ssl_handle = irssi_ssl_get_iochannel(handle, hostname, cert, pkey, cafile, capath, verify);
  if (ssl_handle == NULL) {
    g_io_channel_unref(handle);
    return NULL;
  }
  return ssl_handle;
}
