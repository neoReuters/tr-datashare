package org.icij.datashare.asynctasks.bus.amqp;

import com.rabbitmq.client.BuiltinExchangeType;

/**
 * Enum that provides a registry for all used Queues/Exchanges/routing keys and more generally
 * all settings for the deployed AMQP strategies.
 */
public enum AmqpQueue {

	EVENT  ("exchangeMainEvents",  BuiltinExchangeType.FANOUT, "routingKeyMainEvents"),
	TASK_DLQ  ("exchangeDLQTasks", BuiltinExchangeType.DIRECT, "routingKeyDLQTasks"),
	TASK  ("exchangeMainTasks",  BuiltinExchangeType.DIRECT,"routingKeyMainTasks", TASK_DLQ),
	MANAGER_EVENT_DLQ  ("exchangeDLQManagerEvents",  BuiltinExchangeType.DIRECT,"routingKeyDLQManagerEvent"),
	MANAGER_EVENT  ("exchangeManagerEvents",  BuiltinExchangeType.DIRECT,"routingKeyManagerEvent", MANAGER_EVENT_DLQ),
	WORKER_EVENT("exchangeWorkerEvents", BuiltinExchangeType.FANOUT, "routingKeyWorkerEvents");

	public final String exchange;
	public final String routingKey;
	public final AmqpQueue deadLetterQueue;
	public final BuiltinExchangeType exchangeType;

	AmqpQueue(String exchange, BuiltinExchangeType exchangeType, String routingKey) {
		this(exchange, exchangeType, routingKey, null);
	}
	AmqpQueue(String exchange, BuiltinExchangeType exchangeType, String routingKey, AmqpQueue deadLetterQueue) {
		this.exchange = exchange;
		this.exchangeType = exchangeType;
		this.routingKey = routingKey;
		this.deadLetterQueue = deadLetterQueue;
	}

	@Override public String toString() {
		return String.format("[%s: %s/%s]", name(), exchange, routingKey);
	}
}
