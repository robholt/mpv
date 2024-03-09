#include <unistd.h>
#include <fcntl.h>
#include <libinput.h>
#include <libudev.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <xkbcommon/xkbcommon.h>

#include "common/msg.h"
#include "input.h"
#include "input/keycodes.h"
#include "video/out/wayland_common.h"

static int libinput_open_restricted(const char *path, int flags, void *user_data)
{
    int fd = open(path, flags);
    return fd < 0 ? -1 : fd;
}

static void libinput_close_restricted(int fd, void *user_data)
{
    close(fd);
}

const static struct libinput_interface interface = {
    .open_restricted = libinput_open_restricted,
    .close_restricted = libinput_close_restricted,
};

struct priv {
    int event_fd;
    struct xkb_state *kbd_state;
};

static void handle_keyboard_key(struct mp_input_src *src, struct libinput_event *event)
{
    struct priv *p = src->priv;
    struct libinput_event_keyboard *kbevent = libinput_event_get_keyboard_event(event);
    uint32_t key = libinput_event_keyboard_get_key(kbevent);
    int key_state = libinput_event_keyboard_get_key_state(kbevent) == LIBINPUT_KEY_STATE_PRESSED ? MP_KEY_STATE_DOWN : MP_KEY_STATE_UP;

    xkb_keysym_t sym = xkb_state_key_get_one_sym(p->kbd_state, key+8);
    int mpkey = lookupkey(sym);

    mp_input_put_key(src->input_ctx, mpkey | key_state);
}

static void handle_libinput_event(struct mp_input_src *src, struct libinput_event *event)
{
    enum libinput_event_type event_type = libinput_event_get_type(event);
    switch (event_type) {
        case LIBINPUT_EVENT_KEYBOARD_KEY:
            handle_keyboard_key(src, event);
            break;
        default:
            MP_DBG(src, "unhandled libinput event type: %d\n", event_type);
            break;
    }
}

static void watch_libinput(struct mp_input_src *src, int event_fd, struct libinput *li)
{
    struct epoll_event ev;
    int epollfd = epoll_create1(0);
    if (epollfd == -1) {
        MP_ERR(src, "libinput init: epoll init failed.\n");
        return;
    }

    ev.events = EPOLLIN;
    ev.data.fd = event_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, event_fd, &ev) == -1) {
        MP_ERR(src, "libinput init: failed to register eventfd fd\n");
        return;
    }

    int libinput_fd = libinput_get_fd(li);
    ev.data.fd = libinput_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, libinput_fd, &ev) == -1) {
        MP_ERR(src, "libinput init: failed to register libinput fd\n");
        return;
    }

    struct epoll_event events[2];
    int nfds, n, ret;
    for (;;) {
        nfds = epoll_wait(epollfd, events, 2, -1);
        if (nfds == -1) {
            MP_ERR(src, "libinput: epoll_wait error\n");
            return;
        }

        for (n = 0; n < nfds; n++) {
            if (events[n].data.fd == event_fd) {
                return;
            }
            ret = libinput_dispatch(li);
            if (ret != 0) {
                MP_ERR(src, "libinput: failed to dispatch\n");
                return;
            }
            struct libinput_event *event;
            while ((event = libinput_get_event(li)) != NULL) {
                handle_libinput_event(src, event);
                libinput_event_destroy(event);
            }
        }
    }
}

static void request_cancel(struct mp_input_src *src) {
    MP_VERBOSE(src, "libinput: exiting...");
    struct priv *p = src->priv;
    eventfd_write(p->event_fd, 1);
}

static void uninit(struct mp_input_src *src)
{
    MP_VERBOSE(src, "exited.\n");
}

static void read_libinput_thread(struct mp_input_src *src, void *param)
{
    int event_fd = eventfd(0, EFD_SEMAPHORE| EFD_NONBLOCK);

    struct udev *uctx = udev_new();
    if (!uctx) {
        MP_ERR(src, "failed to create udev context\n");
        mp_input_src_init_done(src);
        return;
    }
    struct libinput *li = libinput_udev_create_context(&interface, NULL, uctx);
    if (!li) {
        MP_ERR(src, "failed to create libinput context\n");
        mp_input_src_init_done(src);
        return;
    }
    if (libinput_udev_assign_seat(li, "seat0") == -1) {
        MP_ERR(src, "failed to setup libinput udev seat\n");
        mp_input_src_init_done(src);
        return;
    }

    struct priv *p = src->priv = talloc_zero(src, struct priv);
    struct xkb_context *xkb_ctx = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    struct xkb_keymap *keymap = xkb_keymap_new_from_names(xkb_ctx, NULL, XKB_KEYMAP_COMPILE_NO_FLAGS);
    p->event_fd = event_fd;
    p->kbd_state = xkb_state_new(keymap);
    src->cancel = request_cancel;
    src->uninit = uninit;
    mp_input_src_init_done(src);

    watch_libinput(src, event_fd, li);

    libinput_unref(li);
}

void mp_input_libinput_add(struct input_ctx *ictx)
{
    mp_input_add_thread_src(ictx, NULL, read_libinput_thread);
}
