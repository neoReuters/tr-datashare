package org.icij.datashare.tasks;

public interface TaskModifier {
    void progress(String taskId, double rate);
}
