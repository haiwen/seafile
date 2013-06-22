#ifndef SIZE_SCHEDULER_H
#define SIZE_SCHEDULER_H

struct _SeafileSession;

struct SizeSchedulerPriv;

typedef struct SizeScheduler {
    struct _SeafileSession *seaf;

    struct SizeSchedulerPriv *priv;
} SizeScheduler;

SizeScheduler *
size_scheduler_new (struct _SeafileSession *session);

int
size_scheduler_start (SizeScheduler *scheduler);

void
schedule_repo_size_computation (SizeScheduler *scheduler, const char *repo_id);

#endif
