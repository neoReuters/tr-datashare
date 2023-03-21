package org.icij.datashare.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;
import org.icij.datashare.Entity;
import org.icij.datashare.text.indexing.IndexId;
import org.icij.datashare.text.indexing.IndexParent;
import org.icij.datashare.text.indexing.IndexRoot;
import org.icij.datashare.text.indexing.IndexType;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY;
import static com.fasterxml.jackson.annotation.PropertyAccessor.FIELD;


/**
 * JSON - POJO Index mapping functions
 *
 * Expect the following annotations from given (domain entity) objects
 * {@link org.icij.datashare.text.indexing.IndexId @IndexId},
 * {@link org.icij.datashare.text.indexing.IndexType @IndexType},
 * {@link com.fasterxml.jackson.annotation.JsonCreator @JSONCreator},
 * {@link com.fasterxml.jackson.annotation.JsonProperty @JSONProperty}
 *
 * Created by julien on 6/29/16.
 */

public class JsonObjectMapper {

    // JSON - Object mapper
    public static final ObjectMapper MAPPER = new ObjectMapper();

    private static final  TypeReference<HashMap<String,Object>> TYPE_REF_MAP_STRING_OBJECT = new TypeReference<>(){};
    public static HashMap<String,Object> getHashMapStringObject(final String mapStr) throws JsonProcessingException {
        CollectionType collectionType = MAPPER.getTypeFactory().constructCollectionType(List.class, TYPE_REF_MAP_STRING_OBJECT.getClass());
        return MAPPER.readValue(mapStr, collectionType);
    }
    private static final   TypeReference<List<Long>> TYPE_REF_LIST_LONG = new TypeReference<>() {};
    public static List<Long> getLongList(final String listStr) throws JsonProcessingException {
        CollectionType collectionType = MAPPER.getTypeFactory().constructCollectionType(List.class, TYPE_REF_LIST_LONG.getClass());
        return MAPPER.readValue(listStr, collectionType);
    }

    static {
        // Handle Optional and other JDK 8 only features
        MAPPER.registerModule(new Jdk8Module());
        // Avoid annotations on domain entities by
        // using compiled methods' metadata
        MAPPER.registerModule(new ParameterNamesModule());
        //  Making domain entities' private fields visible to Jackson
        MAPPER.setVisibility(FIELD, ANY);
    }

    /**
     * Get JSON representation (as a Map) of an Object instance
     *
     * @param obj the object to convert to JSON
     * @param <T> the concrete type of entity
     * @return JSON representation of {@code obj}
     */
    public static <T extends Entity> Map<String, Object> getJson(T obj) {
        String json;
        try {
            json = MAPPER.writeValueAsString(obj);
            return MAPPER.readValue(json, new TypeReference<HashMap<String, Object>>(){});
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T extends Entity> T getObject(String id, String projectId, Map<String, Object> source, Class<T> type) {
        HashMap<String, Object> map;
        if (source == null) {
            map = new HashMap<String, Object>() {{
                put("id", id);
                put("projectId", projectId);
            }};
        } else {
            map = new HashMap<String, Object>() {{putAll(source); put("id", id); put("projectId", projectId);}};
        }
        return getObject(map, type);
    }

    private static <T extends Entity> T getObject(Map<String, Object> source, Class<T> type) {
        try {
            return MAPPER.readValue(MAPPER.writeValueAsString(source), type);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot deserialize object map " + source, e);
        }
    }

    /**
     * Get value of {@link IndexType} annotation from Class
     *
     * @param cls the class holding index type-annotated field
     * @return the index type String
     */
    public static String getType(Class<? extends Entity> cls){
        return cls.getAnnotation(IndexType.class).value();
    }

    /**
     * Get the value of {@link IndexType} annotation
     * from DataShare domain entity Object instance
     *
     * @param obj the object instance from which {@code @IndexType} is extracted
     * @param <T> the concrete type of entity
     * @return the index type String
     */
    public static <T extends Entity> String getType(T obj){
        return getType(obj.getClass());
    }


    /**
     * Get the field value marked with {@link IndexId} from DataShare domain entity object instance
     *
     * @param obj the object holding the index id-annotated field
     * @param <T> the concrete type of entity
     * @return the index id String
     */
    public static <T extends Entity> String getId(T obj) {
        for(Field field : obj.getClass().getDeclaredFields()) {
            if (field.isAnnotationPresent(IndexId.class)) {
                field.setAccessible(true);
                try {
                    return (String) field.get(obj);
                } catch (IllegalAccessException e) {
                    break;
                }
            }
        }
        return null;
    }

    /**
     * Get the field value marked with {@code @IndexParent} from DataShare domain entity object instance
     *
     * @param obj the object holding the index id-annotated field
     * @param <T> the concrete type of entity
     * @return the parent's hash String
     */
    public static <T extends Entity> String getParent(T obj) {
        for(Field field : obj.getClass().getDeclaredFields()) {
            if (field.isAnnotationPresent(IndexParent.class)) {
                field.setAccessible(true);
                try {
                    return (String) field.get(obj);
                } catch (IllegalAccessException e) {
                    break;
                }
            }
        }
        return null;
    }

    public static <T extends Entity> String getRoot(T obj) {
        for (Field field : obj.getClass().getDeclaredFields()) {
            if (field.isAnnotationPresent(IndexRoot.class)) {
                field.setAccessible(true);
                try {
                    return (String) field.get(obj);
                } catch (IllegalAccessException e) {
                    break;
                }
            }
        }
        return null;
    }
}
