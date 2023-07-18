package org.icij.datashare.web;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.StringToClassMapItem;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import net.codestory.http.Context;
import net.codestory.http.annotations.*;
import net.codestory.http.errors.ForbiddenException;
import net.codestory.http.io.InputStreams;
import net.codestory.http.payload.Payload;
import net.codestory.http.types.ContentTypes;
import org.icij.datashare.Repository;
import org.icij.datashare.Repository.AggregateList;
import org.icij.datashare.session.DatashareUser;
import org.icij.datashare.text.Document;
import org.icij.datashare.text.FileExtension;
import org.icij.datashare.text.Tag;
import org.icij.datashare.text.indexing.ExtractedText;
import org.icij.datashare.text.indexing.Indexer;
import org.icij.datashare.text.indexing.SearchedText;
import org.icij.datashare.text.indexing.elasticsearch.SourceExtractor;
import org.icij.datashare.user.User;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.lang.Boolean.parseBoolean;
import static java.util.Arrays.stream;
import static java.util.Optional.ofNullable;
import static net.codestory.http.payload.Payload.ok;
import static org.icij.datashare.text.Project.isAllowed;
import static org.icij.datashare.text.Project.project;

@Singleton
@Prefix("/api")
public class DocumentResource {
    private final Repository repository;
    private final Indexer indexer;

    @Inject
    public DocumentResource(Repository repository, Indexer indexer) {
        this.repository = repository;
        this.indexer = indexer;
    }

    @Operation( description = " Returns the file from the index with the index id and the root document (if embedded document).",
                parameters = {
                    @Parameter(name = "project", description = "project id", in = ParameterIn.PATH),
                    @Parameter(name = "id", description = "hash of the document", in = ParameterIn.PATH),
                    @Parameter(name = "routing", description = "routing key if not a root document", in = ParameterIn.QUERY),
                    @Parameter(name = "inline", description = "if true returns the document as attachment", in = ParameterIn.QUERY),
                    @Parameter(name = "filter_metadata", description = "if true, do not send document metadata", in = ParameterIn.QUERY),
                }
    )
    @ApiResponse(responseCode = "200", content = {@Content(mediaType = "document mime type (from the contentType field or file extension).")},
                 description = "returns the source of the document.")
    @ApiResponse(responseCode = "404", description = "if no document is found")
    @ApiResponse(responseCode = "403", description = "forbidden if the user doesn't have access to the project")
    @Get("/:project/documents/src/:id?routing=:routing&filter_metadata=:filter_metadata")
    public Payload getSourceFile(final String project, final String id,
                                 final String routing, final String filterMetadata, final Context context) throws IOException {
        boolean inline = context.request().query().getBoolean("inline");
        if (((DatashareUser)context.currentUser()).isGranted(project) &&
                isAllowed(repository.getProject(project), context.request().clientAddress())) {
            return routing == null ? getPayload(indexer.get(project, id), project, inline, parseBoolean(filterMetadata)) : getPayload(indexer.get(project, id, routing),project, inline, parseBoolean(filterMetadata));
        }
        throw new ForbiddenException();
    }

    @Operation(description = "Fetch extracted text by slice (pagination)",
                parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "id", description = "the document id", in = ParameterIn.PATH),
                    @Parameter(name = "routing", description = "routing key if not a root document", in = ParameterIn.QUERY),
                    @Parameter(name = "offset", description = "starting byte (starts at 0)", in = ParameterIn.QUERY),
                    @Parameter(name = "limit", description = "Size of the extracted text slice in bytes", in = ParameterIn.QUERY),
                    @Parameter(name = "targetLanguage", description = "Target language (like \"ENGLISH\") to get slice from translated content", in = ParameterIn.QUERY)
                }
    )
    @ApiResponse(responseCode = "200", description = "SON containing the extracted text content (\"content\":text), the max offset as last rank index (\"maxOffset\":number), start (\"start\":number) and size (\"size\":number) parameters")
    @Get("/:project/documents/content/:id?routing=:routing&offset=:offset&limit=:limit&targetLanguage=:targetLanguage")
    public Payload getExtractedText(
            final String project, final String id,  final String routing,
            final Integer offset, final Integer limit, final String targetLanguage, final Context context) throws IOException {
        if (((DatashareUser) context.currentUser()).isGranted(project)) {
            try {
                ExtractedText extractedText;
                if(offset == null && limit == null ){
                    extractedText = getAllExtractedText(id, targetLanguage);
                }else{
                    extractedText = indexer.getExtractedText(project, id, routing, offset, limit, targetLanguage);
                }
                return new Payload(extractedText).withCode(200);
            }
            catch (StringIndexOutOfBoundsException e){
                return new Payload(e.getMessage()).withCode(400);
            }
            catch (IllegalArgumentException e){
                return new Payload(e.getMessage()).withCode(404);
            }
        }
        throw new ForbiddenException();
    }

    @Operation( description = "Search query occurrences in content or translated content (pagination)",
                parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "id", description = "the document id", in = ParameterIn.PATH),
                    @Parameter(name = "routing", description = "routing key if not a root document", in = ParameterIn.QUERY),
                    @Parameter(name = "query", description = "query string to search occurrences", in = ParameterIn.QUERY),
                    @Parameter(name = "targetLanguage", description = "Target language (like \"ENGLISH\") to search in translated content", in = ParameterIn.QUERY)
                }
    )
    @ApiResponse(responseCode = "200", description = "JSON containing the occurrences offsets in the text, and the count of occurrences.")
    @Get("/:project/documents/searchContent/:id?routing=:routing&query=:query&targetLanguage=:targetLanguage")
    public Payload searchOccurrences(
            final String project, final String id,  final String routing,
            final String query, final String targetLanguage, final Context context) throws IOException {
        if (((DatashareUser)context.currentUser()).isGranted(project)) {
            try {
                SearchedText searchedText;
                if(routing == null){
                    searchedText = indexer.searchTextOccurrences(project, id, query, targetLanguage);
                }else{
                    searchedText = indexer.searchTextOccurrences(project, id, routing, query, targetLanguage);
                }
                return new Payload(searchedText).withCode(200);
            }
            catch (StringIndexOutOfBoundsException e){
                return new Payload(e.getMessage()).withCode(400);
            }
            catch (IllegalArgumentException e){
                return new Payload(e.getMessage()).withCode(404);
            }

        }
        throw new ForbiddenException();
    }

    @Operation( description = "Group star the documents. The id list is passed in the request body as a json list.",
                parameters = {
                        @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                },
                requestBody = @RequestBody(content = @Content(mediaType = "application/json", examples = {@ExampleObject(value = "[\"docId1\",\"docId2\"]")}))
    )
    @ApiResponse(responseCode = "200", description = "returns the number of stared documents")
    @Post("/:project/documents/batchUpdate/star")
    public Result<Integer> groupStarProject(final String projectId, final List<String> docIds, Context context) {
        Result<Integer> res = new Result(repository.star(project(projectId), (DatashareUser)context.currentUser(), docIds));
        return new Result<>(repository.star(project(projectId), (DatashareUser)context.currentUser(), docIds));
    }

    @Operation( description = "Group unstar the documents. The id list is passed in the request body as a json list.",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH)
            },
            requestBody = @RequestBody(content = @Content(mediaType = "application/json", examples = {@ExampleObject(value = "[\"docId1\",\"docId2\"]")}))
    )
    @ApiResponse(responseCode = "200", description = "returns the number of unstared documents")
    @Post("/:project/documents/batchUpdate/unstar")
    public Result<Integer> groupUnstarProject(final String projectId, final List<String> docIds, Context context) {
        return new Result<>(repository.unstar(project(projectId), (DatashareUser)context.currentUser(), docIds));
    }

    @Operation(description = "Retrieves the list of starred document for a given project.",
                parameters = {@Parameter(name = "project", description = "the project id", in = ParameterIn.PATH)}
    )
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/:project/documents/starred")
    public List<String> getProjectStarredDocuments(final String projectId, Context context) {
        return repository.getStarredDocuments(project(projectId), (DatashareUser)context.currentUser());
    }

    @Operation(description = "Retrieves the list of tagged document with tag \"tag\" for the given project id.",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "comaSeparatedTags", description = "comma separated tags", in = ParameterIn.PATH)
            }
    )
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/:projects/documents/tagged/:coma_separated_tags")
    public List<String> getProjectTaggedDocuments(final String projectId, final String comaSeparatedTags) {
        return repository.getDocuments(project(projectId),
                stream(comaSeparatedTags.split(",")).map(Tag::tag).toArray(Tag[]::new));
    }

    @Operation(description = "preflight request for document tagging",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "docId", description = "document id", in = ParameterIn.PATH)
            }
    )
    @ApiResponse(responseCode = "200", description = "returns PUT")
    @Options("/:project/documents/tags/:docId")
    public Payload tagDocument(final String projectId, final String docId) {return ok().withAllowMethods("OPTIONS", "PUT");}

    @Operation(description = "document tagging request",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "docId", description = "document id", in = ParameterIn.PATH),
                    @Parameter(name = "routing", description = "document routing if not a root document", in = ParameterIn.QUERY)
            },
            requestBody = @RequestBody(content = @Content(mediaType = "application/json", schema = @Schema(implementation = List.class)))
    )
    @ApiResponse(responseCode = "200", description = "if tag was already in database")
    @ApiResponse(responseCode = "201", description = "if tag was created")
    @Put("/:project/documents/tags/:docId?routing=:routing")
    public Payload tagDocument(final String projectId, final String docId, String routing, Tag[] tags) throws IOException {
        boolean tagSaved = repository.tag(project(projectId), docId, tags);
        indexer.tag(project(projectId), docId, ofNullable(routing).orElse(docId), tags);
        return tagSaved ? Payload.created(): Payload.ok();
    }

    @Operation(description = "request for getting tags from a document id",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "docId", description = "document id", in = ParameterIn.PATH)
            }
    )
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/:project/documents/tags/:docId")
    public List<Tag> getDocumentTags(final String projectId, final String docId) {
        return repository.getTags(project(projectId), docId);
    }

    @Operation(description = "Group tag the documents. The document id list and the tag list are passed in the request body.",
               parameters = {

               },
               requestBody = @RequestBody(
                       content = @Content(mediaType = "application/json",
                       contentSchema = @Schema(requiredProperties = {"docIds", "tags"},
                            properties = {
                               @StringToClassMapItem(key = "docIds", value = List.class),
                               @StringToClassMapItem(key = "tags", value = List.class)
                            }
                       ),
                       examples = {@ExampleObject(value = "{\"docIds\": [\"bd2ef02d39043cc5cd8c5050e81f6e73c608cafde339c9b7ed68b2919482e8dc7da92e33aea9cafec2419c97375f684f\", \"7473df320bee9919abe3dc179d7d2861e1ba83ee7fe42c9acee588d886fe9aef0627df6ae26b72f075120c2c9d1c9b61\"], \"tags\": [\"foo\", \"bar\"]}")}
               ))
    )
    @ApiResponse(responseCode = "200")
    @Post("/:project/documents/batchUpdate/tag")
    public Payload groupTagDocument(final String projectId, BatchTagQuery query, Context context) throws IOException {
        repository.tag(project(projectId), query.docIds, query.tagsAsArray((User)context.currentUser()));
        indexer.tag(project(projectId), query.docIds, query.tagsAsArray((User)context.currentUser()));
        return Payload.ok();
    }

    @Operation(description = "Group untag the documents. The document id list and the tag list are passed in the request body.",
            parameters = {

            },
            requestBody = @RequestBody(
                    content = @Content(mediaType = "application/json",
                            contentSchema = @Schema(requiredProperties = {"docIds", "tags"},
                                    properties = {
                                            @StringToClassMapItem(key = "docIds", value = List.class),
                                            @StringToClassMapItem(key = "tags", value = List.class)
                                    }
                            ),
                            examples = {@ExampleObject(value = "{\"docIds\": [\"bd2ef02d39043cc5cd8c5050e81f6e73c608cafde339c9b7ed68b2919482e8dc7da92e33aea9cafec2419c97375f684f\", \"7473df320bee9919abe3dc179d7d2861e1ba83ee7fe42c9acee588d886fe9aef0627df6ae26b72f075120c2c9d1c9b61\"], \"tags\": [\"foo\", \"bar\"]}")}
                    ))
    )
    @ApiResponse(responseCode = "200")
    @Post("/:project/documents/batchUpdate/untag")
    public Payload groupUntagDocument(final String projectId, BatchTagQuery query,  Context context) throws IOException {
        repository.untag(project(projectId), query.docIds, query.tagsAsArray((User)context.currentUser()));
        indexer.untag(project(projectId), query.docIds, query.tagsAsArray((User)context.currentUser()));
        return Payload.ok();
    }

    @Operation(description = "preflight request for document untagging",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "docId", description = "document id", in = ParameterIn.PATH)
            }
    )
    @ApiResponse(responseCode = "200", description = "returns PUT")
    @Options("/:project/documents/untag/:docId")
    public Payload untagDocument(final String projectId, final String docId) {return ok().withAllowMethods("OPTIONS", "PUT");}

    @Operation(description = "document untagging request",
            parameters = {
                    @Parameter(name = "project", description = "the project id", in = ParameterIn.PATH),
                    @Parameter(name = "docId", description = "document id", in = ParameterIn.PATH),
                    @Parameter(name = "routing", description = "document routing if not a root document", in = ParameterIn.QUERY)
            },
            requestBody = @RequestBody(content = @Content(mediaType = "application/json", schema = @Schema(implementation = List.class)))
    )
    @ApiResponse(responseCode = "200", description = "if tag was not in database")
    @ApiResponse(responseCode = "201", description = "if tag was deleted")
    @Put("/:project/documents/untag/:docId?routing=:routing")
    public Payload untagDocument(final String projectId, final String docId, String routing, Tag[] tags) throws IOException {
        boolean untagSaved = repository.untag(project(projectId), docId, tags);
        indexer.untag(project(projectId), docId, ofNullable(routing).orElse(docId), tags);
        return untagSaved ? Payload.created(): Payload.ok();
    }

    @Operation(description = "Retrieves the list of starred document for all projects for the current user.")
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/documents/starred")
    public List<Document> getStarredDocuments(Context context) {
        return repository.getStarredDocuments((DatashareUser)context.currentUser());
    }

    @Operation(description = "Retrieves the list of users who recommended a document with the total count of recommended documents for the given project id",
            parameters = {@Parameter(name = "project", description = "project id")}
    )
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/users/recommendations?project=:project")
    public AggregateList<User> getProjectRecommendations(final String projectId) {
        return repository.getRecommendations(project(projectId));
    }

    @Operation(description = "Get all users who recommended a document with the count of all recommended documents for project and documents ids.",
            parameters = {
                @Parameter(name = "project", in = ParameterIn.QUERY),
                @Parameter(name = "docIds", in = ParameterIn.QUERY, description = "comma separated document ids")
            }
    )
    @ApiResponse(responseCode = "200", useReturnTypeSchema = true)
    @Get("/users/recommendationsby?project=:project&docIds=:coma_separated_docIds")
    public AggregateList<User> getProjectRecommendations(final String projectId, final String comaSeparatedDocIds) {
        return repository.getRecommendations(project(projectId),stream(comaSeparatedDocIds.split(",")).map(String::new).collect(Collectors.toList()));
    }

    @Operation(description = "Retrieves the set of recommended documents for the given project id and a list of users",
            parameters = {
                    @Parameter(name = "project", in = ParameterIn.PATH),
                    @Parameter(name = "userids", in = ParameterIn.QUERY, description = "comma separated users")
            }
    )
    @Get("/:project/documents/recommendations?userids=:coma_separated_users")
    public Set<String> getProjectRecommentationsBy(final String projectId, final String comaSeparatedUsers) {
        return repository.getRecommentationsBy(project(projectId), stream(comaSeparatedUsers.split(",")).map(User::new).collect(Collectors.toList()));
    }

    @Operation(description = "Group mark the documents as recommended. The id list is passed in the request body as a json list.",
            parameters = {@Parameter(name = "project", in = ParameterIn.PATH)},
            requestBody = @RequestBody(content = @Content(mediaType = "application/json", schema = @Schema(implementation = List.class)))
    )
    @ApiResponse(responseCode = "200", description = "the number of marked documents", useReturnTypeSchema = true)
    @Post("/:project/documents/batchUpdate/recommend")
    public Result<Integer> groupRecommend(final String projectId, final List<String> docIds, Context context) {
        return new Result<>(repository.recommend(project(projectId), (DatashareUser)context.currentUser(), docIds));
    }

    @Operation(description = "Group unmark the documents as recommended. The id list is passed in the request body as a json list.",
            parameters = {@Parameter(name = "project", in = ParameterIn.PATH)},
            requestBody = @RequestBody(content = @Content(mediaType = "application/json", schema = @Schema(implementation = List.class)))
    )
    @ApiResponse(responseCode = "200", description = "the number of unmarked documents", useReturnTypeSchema = true)
    @Post("/:project/documents/batchUpdate/unrecommend")
    public Result<Integer> groupUnrecommend(final String projectId, final List<String> docIds, Context context) {
        return new Result<>(repository.unrecommend(project(projectId), (DatashareUser)context.currentUser(), docIds));
    }

    private ExtractedText getAllExtractedText(final String id, final String targetLanguage) throws IllegalArgumentException {
        //original content (no targetLanguage specified)
        if(targetLanguage == null || targetLanguage.isBlank()){
            String content = repository.getDocument(id).getContent();
            return new ExtractedText(content,0,content.length(),content.length());
        }
        //translated content with targetLanguage
        Iterator<Map<String, String>> translationsIterator = repository.getDocument(id).getContentTranslated().iterator();
        while (translationsIterator.hasNext() ){
            Map<String, String > translation = translationsIterator.next();
            if(translation.get("target_language").equals(targetLanguage)){
                String content=translation.get("content");
                int contentLength = content.length();
                return new ExtractedText(content,0,contentLength,contentLength, targetLanguage);
            }
        }
        // targetLanguage not found
        throw new IllegalArgumentException("Target language not found");
    }

    private Payload getPayload(Document doc, String index, boolean inline, boolean filterMetadata) throws IOException {
        try (InputStream from = new SourceExtractor(filterMetadata).getSource(project(index), doc)) {
            String contentType = ofNullable(doc.getContentType()).orElse(ContentTypes.get(doc.getPath().toFile().getName()));
            Payload payload = new Payload(contentType, InputStreams.readBytes(from));
            String fileName = doc.isRootDocument() ? doc.getName(): doc.getId().substring(0, 10) + "." + FileExtension.get(contentType);
            return inline ? payload: payload.withHeader("Content-Disposition", "attachment;filename=\"" + fileName + "\"");
        } catch (FileNotFoundException fnf) {
            return Payload.notFound();
        }
    }

    private static class BatchTagQuery {
        final List<String> tags;
        final List<String> docIds;

        @JsonCreator
        private BatchTagQuery(@JsonProperty("tags") List<String> tags, @JsonProperty("docIds") List<String> docIds) {
            this.tags = tags;
            this.docIds = docIds;
        }

        Tag[] tagsAsArray(User user) {
            return tags.stream().map(label -> new Tag(label, user)).toArray(Tag[]::new);
        }
    }
}
