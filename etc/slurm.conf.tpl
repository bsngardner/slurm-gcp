# slurm.conf
# https://slurm.schedmd.com/slurm.conf.html
# https://slurm.schedmd.com/configurator.html

ProctrackType=proctrack/cgroup
SlurmctldPidFile=/var/run/slurm/slurmctld.pid
SlurmdPidFile=/var/run/slurm/slurmd-%n.pid
TaskPlugin=task/affinity,task/cgroup
MaxNodeCount=64000

#
#
# SCHEDULING
SchedulerType=sched/backfill
SelectType=select/cons_tres
SelectTypeParameters=CR_Core_Memory

#
#
# LOGGING AND ACCOUNTING
AccountingStoreFlags=job_comment
JobAcctGatherFrequency=30
JobAcctGatherType=jobacct_gather/cgroup
SlurmctldDebug=info
SlurmdDebug=info
DebugFlags=Power

#
#
# TIMERS
MessageTimeout=60

################################################################################
#              vvvvv  WARNING: DO NOT MODIFY SECTION BELOW  vvvvv              #
################################################################################

SlurmctldHost={control_host}({control_addr})

AuthType=auth/{slurm_auth}
AuthInfo=cred_expire=120
AuthAltTypes=auth/jwt
CredType=cred/{slurm_auth}
MpiDefault={mpi_default}
ReturnToService=2
SlurmctldPort={control_host_port}
SlurmdPort=6818
SlurmdSpoolDir=/var/spool/slurmd-%n
SlurmUser=slurm
StateSaveLocation={state_save}

#
#
# LOGGING AND ACCOUNTING
AccountingStorageType=accounting_storage/slurmdbd
AccountingStorageHost={control_host}
ClusterName={name}
SlurmctldLogFile={slurmlog}/slurmctld.log
SlurmdLogFile={slurmlog}/slurmd-%n.log

#
#
# GENERATED CLOUD CONFIGURATIONS
include cloud.conf

################################################################################
#              ^^^^^  WARNING: DO NOT MODIFY SECTION ABOVE  ^^^^^              #
################################################################################
