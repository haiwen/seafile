#ifndef SCHEDULER_H
#define SCHEDULER_H

struct _SeafileSession;

struct SchedulerPriv;

typedef struct Scheduler {
    struct _SeafileSession *seaf;

    struct SchedulerPriv *priv;
} Scheduler;

Scheduler *
scheduler_new (struct _SeafileSession *session);

int
scheduler_init (Scheduler *scheduler);

void
schedule_repo_size_computation (Scheduler *scheduler, const char *repo_id);

#endif
