package org.icij.datashare.tasks;

import com.google.inject.Inject;
import org.icij.datashare.batch.BatchDownload;
import org.icij.datashare.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.icij.datashare.text.Project.project;

public class BatchDownloadLoop {
    public static final BatchDownload POISON = new BatchDownload(project(""), User.nullUser(), "");
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final BlockingQueue<BatchDownload> batchDownloadQueue;
    private final TaskFactory factory;
    private final TaskManager manager;

    @Inject
    public BatchDownloadLoop(BlockingQueue<BatchDownload> batchDownloadQueue, TaskFactory factory, TaskManager manager) {
        this.batchDownloadQueue = batchDownloadQueue;
        this.factory = factory;
        this.manager = manager;
    }

    public void run() {
        logger.info("Datashare running in batch mode. Waiting batch from ds:batchdownload.queue ({})", batchDownloadQueue.getClass());
        BatchDownload currentBatch = null;
        while (!POISON.equals(currentBatch)) {
            try {
                currentBatch = batchDownloadQueue.poll(60, TimeUnit.SECONDS);
                if (!POISON.equals(currentBatch)) {
                    MonitorableFutureTask<File> fileMonitorableFutureTask = new MonitorableFutureTask<>(factory.createDownloadRunner(currentBatch, manager::save));
                    fileMonitorableFutureTask.run();
                    manager.save(new TaskView<>(fileMonitorableFutureTask));
                }
            } catch (Exception ex) {
                logger.error("error in loop", ex);
            }
        }
    }

    public void enqueuePoison() {
        batchDownloadQueue.add(POISON);
    }

    public void close() throws IOException {
        if (batchDownloadQueue instanceof Closeable) {
            ((Closeable) batchDownloadQueue).close();
        }
    }
}
