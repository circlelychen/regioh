from __future__ import absolute_import
from celery import Celery

# make sure chmod 1777 /dev/shm
# or  in fstab
# none           /dev/shm        tmpfs   rw,nodev,nosuid,noexec          0 0
celery = Celery('regioh.celery',
                broker='redis://localhost:6379/0',
                backend='redis://localhost/1',
                include=['regioh.tasks'])
#celery.add_defaults(lambda: app.config)


# Optional configuration, see the application user guide.
celery.conf.update(
    CELERY_TASK_RESULT_EXPIRES=3600,
)

if __name__ == '__main__':
    celery.start()
