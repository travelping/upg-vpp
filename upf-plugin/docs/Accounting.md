# Accounting

## Volume measurements

Volume accounting updates measurements only if PFCP Measurement Method Volume is set.
If volume measurements is not enabled, then traffic measurements are not updated during URR per packet processing.

Volume QUOTA report sent when packet tries to consume quota. It means that reported measurement during volume QUOTA report often a little smaller then quota because of unaccounted last packet.

Because Volume Quota checked before measurement and Volume Threshold checked after measurement it can be that volume threshold report is skipped if volume quota report prevents packet from doing measurement. This shouldn't happen usually, since Volume Threshold is noticeably smaller then Volume Quota.

## Time measurements

Time measurement is very basic and happens only when quota exists. It means that if during some period Volume Quota was consumed, time measurement will not include this time period.

Measurement can be reported larger then provided quota or elapsed time due to timers delay or due to preservation of fraction part of seconds from previous reports in future reports.

## Monitoring time

If monitoring time trigger happens twice, then session will be removed due to inability to store and send two split reports.
