package org.icij.datashare.tasks;

import org.icij.datashare.PropertiesProvider;
import org.icij.datashare.extract.DocumentCollectionFactory;
import org.icij.datashare.text.indexing.elasticsearch.ElasticsearchSpewer;
import org.icij.task.Option;
import org.icij.task.Options;
import org.icij.task.StringOptionParser;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;
import static org.icij.datashare.user.User.nullUser;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class IndexTaskTest {

    @Test
    public void test_options_include_ocr() throws Exception {
        ElasticsearchSpewer spewer = mock(ElasticsearchSpewer.class);
        Mockito.when(spewer.configure(Mockito.any())).thenReturn(spewer);
        IndexTask indexTask = new IndexTask(spewer, mock(DocumentCollectionFactory.class), nullUser(), new PropertiesProvider(new HashMap<>(){{
            put("queueName", "test:queue");
        }}).getProperties());
        Options<String> options = indexTask.options();
        assertThat(options.toString()).contains("ocr=");
    }

    @Test
    public void test_options_include_ocr_language() throws Exception {
        ElasticsearchSpewer spewer = mock(ElasticsearchSpewer.class);
        Mockito.when(spewer.configure(Mockito.any())).thenReturn(spewer);
        IndexTask indexTask = new IndexTask(spewer, mock(DocumentCollectionFactory.class), nullUser(), new PropertiesProvider(new HashMap<>() {{
            put("queueName", "test:queue");
        }}).getProperties());
        Options<String> options = indexTask.options();
        assertThat(options.toString()).contains("ocrLanguage=");
    }

    @Test
    public void test_options_include_language() throws Exception {
        ElasticsearchSpewer spewer = mock(ElasticsearchSpewer.class);
        Mockito.when(spewer.configure(Mockito.any())).thenReturn(spewer);
        IndexTask indexTask = new IndexTask(spewer, mock(DocumentCollectionFactory.class), nullUser(), new PropertiesProvider(new HashMap<>() {{
            put("language", "FRENCH");
            put("queueName", "test:queue");
        }}).getProperties());
        Options<String> options = indexTask.options();
        assertThat(options.toString()).contains("language=");
    }
    
    @Test
    public void test_configure_called_on_spewer() throws Exception {
        ElasticsearchSpewer spewer = mock(ElasticsearchSpewer.class);
        Mockito.when(spewer.configure(Mockito.any())).thenReturn(spewer);
        Map<String, String> options = new HashMap<>() {{
            put("charset", "UTF-16");
        }};
        new IndexTask(spewer, mock(DocumentCollectionFactory.class), nullUser(), new PropertiesProvider(options).getProperties());
        ArgumentCaptor<Options> captor = ArgumentCaptor.forClass(Options.class);
        verify(spewer).configure(captor.capture());
        Option<String> option  = new Option<>("charset", StringOptionParser::new).update("UTF-16");
        assertThat(captor.getValue()).contains(option);
    }
}
