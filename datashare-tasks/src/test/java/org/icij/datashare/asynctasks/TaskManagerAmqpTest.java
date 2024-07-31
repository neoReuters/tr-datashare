package org.icij.datashare.asynctasks;

import org.fest.assertions.Assertions;
import org.icij.datashare.PropertiesProvider;
import org.icij.datashare.asynctasks.bus.amqp.AmqpServerRule;
import org.icij.datashare.asynctasks.bus.amqp.AmqpInterlocutor;
import org.icij.datashare.asynctasks.bus.amqp.AmqpQueue;
import org.icij.datashare.asynctasks.bus.amqp.TaskError;
import org.icij.datashare.user.User;
import org.icij.extract.redis.RedissonClientFactory;
import org.icij.task.Options;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.redisson.Redisson;
import org.redisson.RedissonMap;
import org.redisson.api.RedissonClient;
import org.redisson.command.CommandSyncService;
import org.redisson.liveobject.core.RedissonObjectBuilder;

import static org.fest.assertions.Assertions.assertThat;

public class TaskManagerAmqpTest {
    private static AmqpInterlocutor AMQP;
    @ClassRule static public AmqpServerRule qpid = new AmqpServerRule(5672);
    BlockingQueue<Task<Serializable>> taskQueue = new LinkedBlockingQueue<>();
    TaskManagerAmqp taskManager;
    TaskSupplierAmqp taskSupplier;
    CountDownLatch nextMessage;

    @Test(timeout = 2000)
    public void test_new_task() throws Exception {
        String expectedTaskViewId = taskManager.startTask("taskName", User.local(), Map.of("key", "value"));

        assertThat(taskManager.getTask(expectedTaskViewId)).isNotNull();
        Task<Serializable> actualTaskView = taskQueue.poll(1, TimeUnit.SECONDS);
        Assertions.assertThat(actualTaskView).isNotNull();
        Assertions.assertThat(actualTaskView.id).isEqualTo(expectedTaskViewId);
    }

    @Test(timeout = 2000)
    public void test_new_task_two_workers() throws Exception {
        try (TaskSupplierAmqp otherConsumer = new TaskSupplierAmqp(AMQP)) {
            otherConsumer.consumeTasks(t -> taskQueue.add(t));
            taskManager.startTask("taskName1", User.local(), new HashMap<>());
            taskManager.startTask("taskName2", User.local(), new HashMap<>());

            Task<Serializable> actualTask1 = taskQueue.poll(1, TimeUnit.SECONDS);
            Task<Serializable> actualTask2 = taskQueue.poll(1, TimeUnit.SECONDS);

            Assertions.assertThat(actualTask1).isNotNull();
            Assertions.assertThat(actualTask2).isNotNull();
        }
    }

    @Test(timeout = 2000)
    public void test_task_progress() throws Exception {
        taskManager.startTask("taskName", User.local(), new HashMap<>());

        // in the task runner loop
        Task<Serializable> task = taskQueue.poll(2, TimeUnit.SECONDS); // to sync
        taskSupplier.progress(task.id,0.5);

        nextMessage.await();
        assertThat(taskManager.getTask(task.id).getProgress()).isEqualTo(0.5);
    }

    @Test(timeout = 2000)
    public void test_task_result() throws Exception {
        taskManager.startTask("taskName", User.local(), new HashMap<>());

        // in the task runner loop
        Task<Serializable> task = taskQueue.poll(2, TimeUnit.SECONDS); // to sync
        taskSupplier.result(task.id,"result");

        nextMessage.await();
        assertThat(taskManager.getTask(task.id).getState()).isEqualTo(Task.State.DONE);
        assertThat(taskManager.getTask(task.id).getResult()).isEqualTo("result");
    }

    @Test(timeout = 2000)
    public void test_task_error() throws Exception {
        taskManager.startTask("taskName", User.local(), new HashMap<>());

        // in the task runner loop
        Task<Serializable> task = taskQueue.poll(2, TimeUnit.SECONDS); // to sync
        taskSupplier.error(task.id,new TaskError(new RuntimeException("error in runner")));

        nextMessage.await();
        assertThat(taskManager.getTask(task.id).getResult()).isNull();
        assertThat(taskManager.getTask(task.id).getState()).isEqualTo(Task.State.ERROR);
        assertThat(taskManager.getTask(task.id).error.getMessage()).isEqualTo("error in runner");
    }

    @Test(timeout = 2000)
    public void test_task_canceled() throws Exception {
        taskManager.startTask("taskName", User.local(), new HashMap<>());

        // in the task runner loop
        Task<Serializable> task = taskQueue.poll(2, TimeUnit.SECONDS); // to sync
        taskSupplier.canceled(task,false);

        nextMessage.await();
        assertThat(taskManager.getTask(task.id).getProgress()).isEqualTo(0.0);
        assertThat(taskManager.getTask(task.id).getState()).isEqualTo(Task.State.CANCELLED);
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        AMQP = new AmqpInterlocutor(new PropertiesProvider(new HashMap<>() {{
            put("messageBusAddress", "amqp://admin:admin@localhost?deadLetter=false");
        }}));
        AMQP.createAmqpChannelForPublish(AmqpQueue.TASK);
        AMQP.createAmqpChannelForPublish(AmqpQueue.MANAGER_EVENT);
    }

    @Before
    public void setUp() throws IOException {
        nextMessage = new CountDownLatch(1);
        final RedissonClient redissonClient = new RedissonClientFactory().withOptions(
            Options.from(new PropertiesProvider(Map.of("redisAddress", "redis://redis:6379")).getProperties())).create();
        Map<String, Task<?>> tasks = new RedissonMap<>(new TaskManagerRedis.TaskViewCodec(),
            new CommandSyncService(((Redisson) redissonClient).getConnectionManager(),
                new RedissonObjectBuilder(redissonClient)),
            "tasks:queue:test",
            redissonClient,
            null,
            null
        );
        taskManager = new TaskManagerAmqp(AMQP, tasks, () -> nextMessage.countDown());
        taskSupplier = new TaskSupplierAmqp(AMQP);
        taskSupplier.consumeTasks(t -> taskQueue.add(t));
    }

    @After
    public void tearDown() throws Exception {
        taskQueue.clear();
        taskManager.clear();
        taskManager.stopAllTasks(User.local());
        taskSupplier.close();
        taskManager.close();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        AMQP.close();
    }
}