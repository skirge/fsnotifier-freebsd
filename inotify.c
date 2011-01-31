/*
 * Copyright 2000-2010 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * FreeBSD port done by Sebastian Chmielewski <skirge84@o2.pl>
 *
 */

#include "fsnotifier.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sysexits.h>
#include <fcntl.h>
#include <err.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>


#define DEFAULT_SUBDIR_COUNT 5

#define CHECK_NULL(p) if (p == NULL)  { userlog(LOG_ERR, "out of memory"); return ERR_ABORT; }


static int inotify_fd = -1;
static int watch_count = 1000000;
static table* watches;
static bool limit_reached = false;
static void (* callback)(char*, int) = NULL;
#define EVENT_SIZE (sizeof(struct kevent))
#define EVENT_BUF_LEN (2048 * (EVENT_SIZE + 16))
static struct kevent event_buf[2048];


bool init_inotify() {
	inotify_fd = kqueue();
	if (inotify_fd < 0) {
		userlog(LOG_ERR, "inotify_init: %s", strerror(errno));
		return false;
	}
	userlog(LOG_DEBUG, "inotify fd: %d", get_inotify_fd());
	userlog(LOG_INFO, "inotify watch descriptors: %d", watch_count);

	watches = table_create(watch_count);
	if (watches == NULL) {
		userlog(LOG_ERR, "out of memory");
		close(inotify_fd);
		inotify_fd = -1;
		return false;
	}

	return true;
}


inline void set_inotify_callback(void (* _callback)(char*, int)) {
	callback = _callback;
}


inline int get_inotify_fd() {
	return inotify_fd;
}


inline int get_watch_count() {
	return watch_count;
}


inline bool watch_limit_reached() {
	return limit_reached;
}


static int add_watch(const char* path, watch_node* parent,int isdir, int isevent) {
	userlog(LOG_DEBUG,"add_watch: Trying to add path:%s for parent:%s",path,parent?parent->name:"(null)");	

	if(parent == NULL ) {
		for(int i = 0; i < array_size(ROOTS); i++) {
			watch_node* node = array_get(ROOTS, i);
			if(node!=NULL && node->name!=NULL && strcmp(node->name,path) == 0) {
				userlog(LOG_DEBUG,"add_watch: node is already under ROOTS");
				return node->wd;
			}
		}
	} else {
		if (parent->name!=NULL && strcmp(parent->name,path)==0) {
			userlog(LOG_DEBUG,"add_watch: node is the same as parent");
			return parent->wd;
		}
		if(parent->kids != NULL) {
			for(int i = 0; i< array_size(parent->kids); i++) {
				watch_node* kid = array_get(parent->kids, i);
				if(kid!=NULL && strcmp(kid->name, path)==0) {
					userlog(LOG_DEBUG,"add_watch: node is already under parent");
					return kid->wd;
				}
			}
		}
	}


	struct kevent eventlist[2];
	int nevents = 0;
	int wd = open(path, O_RDONLY);
	if(wd < 0 ) {
		userlog(LOG_ERR, "add_watch, cannot open: %s, err:%s", path, strerror(errno));
		return ERR_CONTINUE;
	}
	EV_SET(&eventlist[0], wd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
			NOTE_DELETE | NOTE_WRITE | NOTE_RENAME
			| NOTE_EXTEND | NOTE_ATTRIB | NOTE_REVOKE,
			0, NULL);
	nevents++;

	if(kevent(inotify_fd, eventlist, 
				nevents, NULL, 0, NULL) < 0) {
		userlog(LOG_ERR, "kevent add event failed for: %s, %s", path, strerror(errno));
		err(EX_IOERR, "kevent add event failed for: %s",path);
	} else {
		userlog(LOG_DEBUG, "watching %s: %d", path, wd);
	}

	watch_node* node = table_get(watches, wd);
	if (node != NULL) {
		if (node->wd != wd || strcmp(node->name, path) != 0) {
			userlog(LOG_ERR, "table error: collision (new %d:%s, existing %d:%s)", wd, path, node->wd, node->name);
			return ERR_ABORT;
		}

		return wd;
	}

	node = calloc(1,sizeof(watch_node));

	CHECK_NULL(node);
	node->name = strdup(path);
	CHECK_NULL(node->name);
	node->wd = wd;
	node->parent = parent;
	node->isdir = isdir;
	node->kids = NULL;


	if(parent!=NULL) {
		if(parent->kids == NULL) {
			parent->kids = array_create(DEFAULT_SUBDIR_COUNT);
			CHECK_NULL(parent->kids);
		}
		CHECK_NULL(array_push(parent->kids, node));
	}


	if (table_put(watches, wd, node) == NULL) {
		userlog(LOG_ERR, "table error: unable to put (%d:%s)", wd, path);
		return ERR_ABORT;
	}

	if(isevent) {
		output("CREATE\n%s\n",path);
	}
	return wd;
}


static void rm_watch(int wd, bool update_parent) {
	watch_node* node = table_get(watches, wd);
	if (node == NULL) {
		return;
	}

	userlog(LOG_DEBUG, "unwatching %s: %d (%p)", node->name, node->wd, node);
	struct kevent eventlist[2];
	int nevents=0;
	EV_SET(&eventlist[0], wd, EVFILT_VNODE, EV_DELETE, 
			NOTE_DELETE | NOTE_WRITE | NOTE_RENAME
			| NOTE_EXTEND | NOTE_ATTRIB | NOTE_REVOKE,
			0, NULL);
	nevents++;

	if(kevent(inotify_fd, eventlist, 
				nevents, NULL, 0, NULL) < 0) {
		userlog(LOG_ERR, "kevent remove watch: %s, error:%s", node->name, strerror(errno));
		err(EX_OSERR, "kevent remove watch: %s, error:%s", node->name, strerror(errno));
	}
	for (int i=0; i<array_size(node->kids); i++) {
		watch_node* kid = array_get(node->kids, i);
		if (kid != NULL) {
			rm_watch(kid->wd, false);
		}
	}

	if (update_parent && node->parent != NULL) {
		for (int i=0; i<array_size(node->parent->kids); i++) {
			if (array_get(node->parent->kids, i) == node) {
				array_put(node->parent->kids, i, NULL);
				break;
			}
		}
	}

	free(node->name);
	array_delete(node->kids);
	free(node);
	table_put(watches, wd, NULL);
	if(close(wd) < 0) {
		userlog(LOG_WARNING,"close: %s, %s", node->name, strerror(errno));
	}
}


static bool is_directory(struct dirent* entry, const char* path) {
	if (entry->d_type == DT_DIR) {
		return true;
	}
	else if (entry->d_type == DT_UNKNOWN) {  // filesystem doesn't support d_type
		struct stat st;
		return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
	}
	return false;
}

static bool is_ignored(const char* path, array* ignores) {

	if(strstr(path, ".svn") != NULL || strstr(path, ".git") !=NULL || strstr(path, ".hg") != NULL) { /* hidden directory */
		return true;
	}

	if (ignores != NULL) {
		int pl = strlen(path);
		for (int i=0; i<array_size(ignores); i++) {
			const char* ignore = array_get(ignores, i);
			int il = strlen(ignore);
			if ((pl >= il && strncmp(path, ignore, il) == 0) ||
					(strncmp(path+(pl-il),ignore,il)==0)) {
				userlog(LOG_DEBUG, "path %s is under unwatchable %s - ignoring", path, ignore);
				return true;
			}
		}
	}

	return false;
}

static int walk_tree(const char* path, watch_node* parent, array* ignores, int isevent) {

	if (is_ignored(path, ignores)) {
		return ERR_IGNORE;
	}

	DIR* dir = opendir(path);
	if (dir == NULL) {
		if (errno == EACCES) {
			return ERR_IGNORE;
		} else if (errno == ENOTDIR) {  // flat root
			return add_watch(path, parent, 0, isevent);
		}
		userlog(LOG_ERR, "opendir(%s): %s", path, strerror(errno));
		return ERR_IGNORE;
	}

	int id = add_watch(path, parent, 1, isevent);
	if (id < 0 && id != ERR_IGNORE) {
		userlog(LOG_DEBUG,"add_watch nonignorable error code id:%d",id);
		if(closedir(dir) < 0) {
			userlog(LOG_WARNING,"closedir: %s, %s", dir, strerror(errno));
		}
		return id;
	}

	struct dirent* entry;
	char subdir[PATH_MAX+PATH_MAX+1];

	strcpy(subdir, path);

	if (subdir[strlen(subdir) - 1] != '/') {
		strcat(subdir, "/");
	}

	char* p = subdir + strlen(subdir);

	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, ".",PATH_MAX) == 0 || strncmp(entry->d_name, "..",PATH_MAX) == 0) {
			continue;
		}

		strncpy(p, entry->d_name,PATH_MAX);
		if(is_directory(entry, subdir)) {
			int subdir_id = walk_tree(subdir, table_get(watches, id), ignores, isevent);
			if (subdir_id < 0 && subdir_id != ERR_IGNORE) {
				rm_watch(id, true);
				id = subdir_id;
				break;
			}
		} else {
			add_watch(subdir, table_get(watches, id), 0, isevent);
		}
	}

	if(closedir(dir) < 0 ) {
		userlog(LOG_WARNING,"closedir: %s, %s", dir, strerror(errno));
	}

	return id;
}


int watch(const char* root, watch_node* parent, array* ignores) {
	char buf[PATH_MAX];
	const char* normalized = realpath(root, buf);
	return walk_tree((normalized != NULL ? normalized : root), parent, ignores, 0);
}


void unwatch(int id) {
	rm_watch(id, true);
}

static bool process_inotify_event(struct kevent* event) {
	watch_node* node = table_get(watches, event->ident);
	if (node == NULL) {
		return true;
	}
	userlog(LOG_DEBUG, "inotify: ident=%d filter=%d flags=%d fflags=%d data=%d udata=%d name=%s",
			event->ident, event->filter , event->flags, event->fflags, event->data, event->udata , node->name);
	char path[PATH_MAX];
	strcpy(path, node->name);
	if (node->isdir && (event->filter == EVFILT_VNODE) && 
			((event->fflags & NOTE_WRITE) || (event->fflags & NOTE_EXTEND) || 
			 (event->fflags & NOTE_LINK))) {
		userlog(LOG_DEBUG, "write detected in path:%s, fd:%d, filter:%d, fflags:%d", path, event->ident, event->filter, event->fflags);
		int result = walk_tree(path, node->parent, NULL, 1);
		if (result < 0 && result != ERR_IGNORE) {
			return false;
		}
	}
	if((event->filter == EVFILT_VNODE) && 
			(((event->fflags & NOTE_DELETE) || (event->fflags & NOTE_REVOKE))
			 || (event->fflags & NOTE_RENAME))) {
		userlog(LOG_DEBUG, "remove, revoke or rename in path:%s, fd:%d, filter:%d, fflags:%d", path, event->ident, event->filter, event->fflags);
		if (node->isdir) {
			for (int i=0; i<array_size(node->kids); i++) {
				watch_node* kid = array_get(node->kids, i);
				if (kid != NULL 
						&& strncmp(kid->name, path,PATH_MAX) == 0) {
					userlog(LOG_DEBUG,"remove watch for:%s, wd: %d",kid->name, kid->wd);
					rm_watch(kid->wd, false);
					array_put(node->kids, i, NULL);
					break;
				}
			}
		}
		rm_watch(node->wd,true);
	}

	if (callback != NULL) {
		(*callback)(path, event->fflags);
	}
	return true;
}

struct KEVENT_FLAGS {
	u_short flags;
	const char* desc;
};

#define KEVENT_FLAG(x) { x, #x }

struct KEVENT_FILTERS { 
	short filter;
	const char* desc;
};

struct KEVENT_FFLAGS {
	u_int fflags;
	const char* desc;
};

void decode_event(struct kevent* event)
{
	struct KEVENT_FLAGS kevent_flags[] = {
		KEVENT_FLAG(EV_ADD),
		KEVENT_FLAG(EV_ENABLE),
		KEVENT_FLAG(EV_DISABLE),
		KEVENT_FLAG(EV_DISPATCH),
		KEVENT_FLAG(EV_DELETE),
		KEVENT_FLAG(EV_RECEIPT),
		KEVENT_FLAG(EV_ONESHOT),
		KEVENT_FLAG(EV_CLEAR),
		KEVENT_FLAG(EV_EOF),
		KEVENT_FLAG(EV_ERROR)
	};

	struct KEVENT_FILTERS kevent_filters[] = {
		KEVENT_FLAG(EVFILT_READ),
		KEVENT_FLAG(EVFILT_WRITE),
		KEVENT_FLAG(EVFILT_AIO),
		KEVENT_FLAG(EVFILT_VNODE),
		KEVENT_FLAG(EVFILT_PROC),
		KEVENT_FLAG(EVFILT_SIGNAL),
		KEVENT_FLAG(EVFILT_TIMER),
		KEVENT_FLAG(EVFILT_FS),
		KEVENT_FLAG(EVFILT_LIO),
		KEVENT_FLAG(EVFILT_USER),
		KEVENT_FLAG(EVFILT_SYSCOUNT)
	};

	struct KEVENT_FFLAGS kevent_fflags[] = {
		KEVENT_FLAG(NOTE_DELETE),
		KEVENT_FLAG(NOTE_WRITE),
		KEVENT_FLAG(NOTE_EXTEND),
		KEVENT_FLAG(NOTE_ATTRIB),
		KEVENT_FLAG(NOTE_LINK),
		KEVENT_FLAG(NOTE_RENAME),
		KEVENT_FLAG(NOTE_REVOKE),
		KEVENT_FLAG(NOTE_LOWAT),
		KEVENT_FLAG(NOTE_FFNOP),
		KEVENT_FLAG(NOTE_FFAND),
		KEVENT_FLAG(NOTE_FFOR),
		KEVENT_FLAG(NOTE_FFCOPY),
		KEVENT_FLAG(NOTE_FFCTRLMASK),
		KEVENT_FLAG(NOTE_FFLAGSMASK)
	};

	userlog(LOG_DEBUG,"kevent received: ident: %d, ", event->ident);

	for(int i = 0; i<sizeof(kevent_flags)/sizeof(struct KEVENT_FLAGS);
			++i)
	{
		if(event->flags & kevent_flags[i].flags) {
			userlog(LOG_DEBUG,"flag for event: %s",kevent_flags[i].desc);
		}
	}

	for(int i = 0; i<sizeof(kevent_filters)/sizeof(struct KEVENT_FILTERS);
			++i)
	{
		if(event->filter == kevent_filters[i].filter) {
			userlog(LOG_DEBUG,"filter for event: %s",kevent_filters[i].desc);
		}
	}

	for(int i = 0; i<sizeof(kevent_fflags)/sizeof(struct KEVENT_FFLAGS);
			++i)
	{
		if(event->fflags & kevent_fflags[i].fflags) {
			userlog(LOG_DEBUG,"fflag for event: %s",kevent_fflags[i].desc);
		}
	}

	userlog(LOG_DEBUG,"=========================================");

}

bool process_inotify_input() {
	size_t len = kevent(inotify_fd,NULL,0,event_buf,2048,NULL);
	if (len < 0) {
		userlog(LOG_ERR, "read: %s", strerror(errno));
		return false;
	}

	int i = 0;
	while (i < len) {
		struct kevent* event = &event_buf[i];
		if(event->flags & EV_ERROR) {
			userlog(LOG_ERR,"kevent: error returned in kevent",strerror(event->data));
			return false;
		}
		if(level == LOG_DEBUG) {
			decode_event(event);
		}
		i++;
		if (!process_inotify_event(event)) {
			return false;
		}
	}

	return true;
}


void close_inotify() {
	if (watches != NULL) {
		table_delete(watches);
	}

	if (inotify_fd >= 0) {
		close(inotify_fd);
	}
}
