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
 */

#include "fsnotifier.h"

#include <dirent.h>
#include <errno.h>
#ifdef linux
	#include <linux/limits.h>
#else
	#include <limits.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef linux
	#include <sys/inotify.h>
#else
	#include <sys/types.h>
	#include <sys/event.h>
	#include <sys/time.h>
	#include <sysexits.h>
	#include <fcntl.h>
	#include <err.h>
#endif /* defined linux */
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>


#define WATCH_COUNT_NAME "/proc/sys/fs/inotify/max_user_watches"

#define DEFAULT_SUBDIR_COUNT 5

#define CHECK_NULL(p) if (p == NULL)  { userlog(LOG_ERR, "out of memory"); return ERR_ABORT; }

typedef struct __watch_node {
  char* name;
  int wd;
  struct __watch_node* parent;
  array* kids;
} watch_node;

static int inotify_fd = -1;
static int watch_count = 1000000;
static table* watches;
static bool limit_reached = false;
static void (* callback)(char*, int) = NULL;
#ifdef linux
#define EVENT_SIZE (sizeof(struct inotify_event))
#else
#define EVENT_SIZE (sizeof(struct kevent))
#endif /* defined linux */
#define EVENT_BUF_LEN (2048 * (EVENT_SIZE + 16))
#ifdef linux
static char event_buf[EVENT_BUF_LEN];
#else
static struct kevent event_buf[2048];
#endif /* defined linux */

#ifdef linux
static void read_watch_descriptors_count() {
  FILE* f = fopen(WATCH_COUNT_NAME, "r");
  if (f == NULL) {
    userlog(LOG_ERR, "can't open %s: %s", WATCH_COUNT_NAME, strerror(errno));
    return;
  }

  char* str = read_line(f);
  if (str == NULL) {
    userlog(LOG_ERR, "can't read from %s", WATCH_COUNT_NAME);
  }
  else {
    watch_count = atoi(str);
  }

  fclose(f);
}
#endif


bool init_inotify() {
#ifdef linux
  inotify_fd = inotify_init();
#else
  inotify_fd = kqueue();
#endif /* defined linux */
  if (inotify_fd < 0) {
    userlog(LOG_ERR, "inotify_init: %s", strerror(errno));
    return false;
  }
  userlog(LOG_DEBUG, "inotify fd: %d", get_inotify_fd());
#ifdef linux
  read_watch_descriptors_count();
  if (watch_count <= 0) {
    close(inotify_fd);
    inotify_fd = -1;
    return false;
  }
#endif
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


static int add_watch(const char* path, watch_node* parent) {
#ifdef linux
  int wd = inotify_add_watch(inotify_fd, path, IN_MODIFY | IN_ATTRIB | IN_CREATE | IN_DELETE | IN_MOVE | IN_DELETE_SELF);
  if (wd < 0) {
    if (errno == ENOSPC) {
      limit_reached = true;
    }
    userlog(LOG_ERR, "inotify_add_watch(%s): %s", path, strerror(errno));
    return ERR_CONTINUE;
  }
#else
  struct kevent eventlist[2];
  int nevents = 0;
  int wd = open(path, O_RDONLY);
  if(wd < 0 ) {
	  userlog(LOG_ERR, "add_watch, cannot open: %s, err:%s", path, strerror(errno));
	  return ERR_CONTINUE;
  }
  EV_SET(&eventlist[0], wd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
		  NOTE_DELETE | NOTE_WRITE | NOTE_RENAME
		  /*| NOTE_EXTEND | NOTE_ATTRIB | 
		  NOTE_LINK | NOTE_RENAME | NOTE_REVOKE*/, 
		  0, NULL);
  nevents++;
/*
  EV_SET(&eventlist[1], wd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 
		  0, 0, NULL);
	nevents++;
*/
  if(kevent(inotify_fd, eventlist, 
			  nevents, NULL, 0, NULL) < 0) {
	  userlog(LOG_ERR, "kevent add event failed for: %s, %s", path, strerror(errno));
	  err(EX_IOERR, "kevent add event failed for: %s",path);
  }
#endif /* defined linux */
  else {
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

  node = malloc(sizeof(watch_node));

  CHECK_NULL(node);
  node->name = strdup(path);
  CHECK_NULL(node->name);
  node->wd = wd;
  node->parent = parent;
  node->kids = NULL;

  if (parent != NULL) {
    if (parent->kids == NULL) {
      parent->kids = array_create(DEFAULT_SUBDIR_COUNT);
      CHECK_NULL(parent->kids);
    }
    CHECK_NULL(array_push(parent->kids, node));
  }

  if (table_put(watches, wd, node) == NULL) {
    userlog(LOG_ERR, "table error: unable to put (%d:%s)", wd, path);
    return ERR_ABORT;
  }

  return wd;
}


static void rm_watch(int wd, bool update_parent) {
  watch_node* node = table_get(watches, wd);
  if (node == NULL) {
    return;
  }

  userlog(LOG_DEBUG, "unwatching %s: %d (%p)", node->name, node->wd, node);
#ifdef linux
  if (inotify_rm_watch(inotify_fd, node->wd) < 0) {
    userlog(LOG_DEBUG, "inotify_rm_watch(%d:%s): %s", node->wd, node->name, strerror(errno));
  }
#else
  struct kevent eventlist[2];
  int nevents=0;
  EV_SET(&eventlist[0], wd, EVFILT_VNODE, EV_DELETE, 
		  NOTE_DELETE | NOTE_WRITE | NOTE_RENAME
		  /*| NOTE_EXTEND | NOTE_ATTRIB | 
		  NOTE_LINK | NOTE_RENAME | NOTE_REVOKE*/, 
		  0, NULL);
	nevents++;
/*
  EV_SET(&eventlist[1], wd, EVFILT_READ, EV_DELETE, 
		  0, 0, NULL);
	nevents++;
*/
  if(kevent(inotify_fd, eventlist, 
			  nevents, NULL, 0, NULL) < 0) {
	  userlog(LOG_ERR, "kevent remove watch: %s, error:%s", node->name, strerror(errno));
	  err(EX_OSERR, "kevent remove watch: %s, error:%s", node->name, strerror(errno));
  }
#endif
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

  if(strstr(path, "/.") != NULL) { /* hidden directory */
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

static int walk_tree(const char* path, watch_node* parent, array* ignores) {
  if (is_ignored(path, ignores)) {
    return ERR_IGNORE;
  }

  DIR* dir = opendir(path);
  if (dir == NULL) {
    if (errno == EACCES) {
      return ERR_IGNORE;
    }
/*
    else if (errno == ENOTDIR) {  // flat root
      return add_watch(path, parent);
    }
*/
    userlog(LOG_ERR, "opendir(%s): %s", path, strerror(errno));
    return ERR_CONTINUE;
  }

  int id = add_watch(path, parent);
  if (id < 0) {
    if(closedir(dir) < 0) {
		userlog(LOG_WARNING,"closedir: %s, %s", dir, strerror(errno));
	}
    return id;
  }

  struct dirent* entry;
  char subdir[PATH_MAX];
  strcpy(subdir, path);
  if (subdir[strlen(subdir) - 1] != '/') {
    strcat(subdir, "/");
  }
  char* p = subdir + strlen(subdir);

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    strcpy(p, entry->d_name);
#if 1
    if (!is_directory(entry, subdir)) {
      continue;
    }
#else
	if(!is_directory(entry, subdir)) {
		add_watch(subdir, parent);
	} else {
#endif
    int subdir_id = walk_tree(subdir, table_get(watches, id), ignores);
    if (subdir_id < 0 && subdir_id != ERR_IGNORE) {
      rm_watch(id, true);
      id = subdir_id;
      break;
    }
  }
#if 0
  }
#endif

  if(closedir(dir) < 0 ) {
		userlog(LOG_WARNING,"closedir: %s, %s", dir, strerror(errno));
  }
  return id;
}


int watch(const char* root, array* ignores) {
  char buf[PATH_MAX];
  const char* normalized = realpath(root, buf);
  return walk_tree((normalized != NULL ? normalized : root), NULL, ignores);
}


void unwatch(int id) {
  rm_watch(id, true);
}

#ifdef linux
static bool process_inotify_event(struct inotify_event* event) {
#else
static bool process_inotify_event(struct kevent* event) {
#endif /* defined linux */
#ifdef linux
  watch_node* node = table_get(watches, event->wd);
#else
  watch_node* node = table_get(watches, event->ident);
#endif
  if (node == NULL) {
    return true;
  }
#ifdef linux
  userlog(LOG_DEBUG, "inotify: wd=%d mask=%d dir=%d name=%s",
      event->wd, event->mask & (~IN_ISDIR), (event->mask & IN_ISDIR) != 0, node->name);
#else
  userlog(LOG_DEBUG, "inotify: ident=%d filter=%d flags=%d fflags=%d data=%d udata=%d name=%s",
      event->ident, event->filter , event->flags, event->fflags, event->data, event->udata , node->name);
#endif /*defined linux */
  char path[PATH_MAX];
  strcpy(path, node->name);
#ifdef linux
  if (event->len > 0) {
    if (path[strlen(path) - 1] != '/') {
      strcat(path, "/");
    }
    strcat(path, event->name);
  }
#endif
#ifdef linux
  if ((event->mask & IN_CREATE || event->mask & IN_MOVED_TO) && event->mask & IN_ISDIR) {
#else
  if ((event->filter == EVFILT_VNODE) && 
		  ((event->fflags & NOTE_WRITE) || (event->fflags & NOTE_EXTEND) || 
		   (event->fflags & NOTE_LINK))) {
#endif /* defined linux */
	userlog(LOG_DEBUG, "write detected in path:%s, fd:%d", path, event->ident);
#ifdef linux /* do not process directories on write event under FreeBSD */
    int result = walk_tree(path, node, NULL);
    if (result < 0 && result != ERR_IGNORE) {
      return false;
    }
#endif
  }
#ifdef linux
  if ((event->mask & IN_DELETE || event->mask & IN_MOVED_FROM) && event->mask & IN_ISDIR) {
#else
  if ((event->filter == EVFILT_VNODE) && 
		  ((event->fflags & NOTE_DELETE) || (event->fflags & NOTE_REVOKE))
		  || (event->fflags & NOTE_RENAME)) {
#endif /* defined linux */
	userlog(LOG_DEBUG, "remove, revoke or rename in path:%s, fd:%d", path, event->ident);
    for (int i=0; i<array_size(node->kids); i++) {
      watch_node* kid = array_get(node->kids, i);
      if (kid != NULL && strcmp(kid->name, path) == 0) {
        rm_watch(kid->wd, false);
        array_put(node->kids, i, NULL);
        break;
      }
    }
  }

  if (callback != NULL) {
#ifdef linux
    (*callback)(path, event->mask);
#else
    (*callback)(path, event->fflags);
#endif /* defined linux */
  }
  return true;
}

bool process_inotify_input() {
#ifdef linux
  size_t len = read(inotify_fd, event_buf, EVENT_BUF_LEN);
#else
  size_t len = kevent(inotify_fd,NULL,0,event_buf,2048,NULL);
#endif
  if (len < 0) {
    userlog(LOG_ERR, "read: %s", strerror(errno));
    return false;
  }

  int i = 0;
  while (i < len) {
#ifdef linux
    struct inotify_event* event = (struct inotify_event*) &event_buf[i];
    i += EVENT_SIZE + event->len;

    if (event->mask & IN_IGNORED) {
      continue;
    }
    if (event->mask & IN_Q_OVERFLOW) {
      userlog(LOG_ERR, "event queue overflow");
      continue;
    }
#else
	struct kevent* event = &event_buf[i];
	i++;
#endif /* defined linux */
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
