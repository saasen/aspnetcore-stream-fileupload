using System.Net;
using System.Text;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using Overby.Extensions.AsyncBinaryReaderWriter;

namespace Web.Controllers;

[ApiController]
[Route("[controller]")]
public class MultiPartController : ControllerBase
{
    // Source: https://en.wikipedia.org/wiki/List_of_file_signatures
    // To read the first bytes of a file you can use the following command on UNIX systems:
    // od -t x1 -N 10 <filename>
    private static readonly Dictionary<string, List<byte[]>> _fileSignature = new()
    {
        { ".gif", new List<byte[]> { new byte[] { 0x47, 0x49, 0x46, 0x38 } } },
        { ".png", new List<byte[]> { new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } } },
        { ".jpeg", new List<byte[]>
            {
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE2 },
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE3 },
            }
        },
        { ".jpg", new List<byte[]>
            {
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 },
                new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 },
            }
        },
        { ".zip", new List<byte[]> 
            {
                new byte[] { 0x50, 0x4B, 0x03, 0x04 }, 
                new byte[] { 0x50, 0x4B, 0x4C, 0x49, 0x54, 0x45 },
                new byte[] { 0x50, 0x4B, 0x53, 0x70, 0x58 },
                new byte[] { 0x50, 0x4B, 0x05, 0x06 },
                new byte[] { 0x50, 0x4B, 0x07, 0x08 },
                new byte[] { 0x57, 0x69, 0x6E, 0x5A, 0x69, 0x70 },
            }
        },
        { ".pdf", new List<byte[]> { new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D } } },
        { ".doc", new List<byte[]> { new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 } } },
        { ".docx", new List<byte[]>
            {
                new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 },
                new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 }
            }
        },
        { ".xls", new List<byte[]> { new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 } } },
        { ".xlsx", new List<byte[]>
            {
                new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 },
                new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 }
            }
        },
    };
    
    private const long MaxFileUploadSize = 1024L * 1024L * 100L; // 100 MB
    
    private readonly ILogger<MultiPartController> _logger;

    public MultiPartController(ILogger<MultiPartController> logger)
    {
        _logger = logger;
    }

    [HttpPost("upload/{customerId}/{documentId}")]
    [DisableFormValueModelBinding]
    [RequestSizeLimit(MaxFileUploadSize)]
    [RequestFormLimits(MultipartBodyLengthLimit = MaxFileUploadSize)]
    public async Task<IActionResult> UploadFile([FromRoute] string customerId, [FromRoute] string documentId, CancellationToken ct)
    {
        var request = HttpContext.Request;
        
        if (!request.HasFormContentType ||
            !MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaTypeHeader) ||
            string.IsNullOrEmpty(mediaTypeHeader.Boundary.Value))
        {
            return new UnsupportedMediaTypeResult();
        }

        // TODO: Do we need to reset the stream position here since other middleware could've read parts already?
        // request.Body.Seek(0, SeekOrigin.Begin);
        
        var boundary = HeaderUtilities.RemoveQuotes(mediaTypeHeader.Boundary.Value).Value;
        var reader = new MultipartReader(boundary, request.Body);
        var section = await reader.ReadNextSectionAsync(ct);

        while (section != null)
        {
            var hasContentDispositionHeader = ContentDispositionHeaderValue.TryParse(section.ContentDisposition,
                out var contentDisposition);

            if (!hasContentDispositionHeader)
            {
                section = await reader.ReadNextSectionAsync(ct);
            }

            if (contentDisposition.HasFileContentDisposition())
            {
                var trustedFileName = WebUtility.HtmlEncode(contentDisposition.FileName.Value);

                // We can only read the HTTP request stream once, so we need to copy it to a memory stream
                // We are reading at least twice, once because we check the file extension, and secondly when uploading the file to Azure
                // Ref. https://devblogs.microsoft.com/dotnet/re-reading-asp-net-core-request-bodies-with-enablebuffering/

                using (var binaryReader = new AsyncBinaryReader(section.Body))
                {
                    var ext = Path.GetExtension(trustedFileName).ToLowerInvariant();
                    var signatures = _fileSignature[ext];
                    var headerBytes = await binaryReader.ReadBytesAsync(signatures.Max(m => m.Length));
                    
                    var matchesFile = signatures.Any(signature => 
                        headerBytes.Take(signature.Length).SequenceEqual(signature));
                
                    if (!matchesFile)
                    {
                        throw new Exception("We dont support this file");
                    }
                }

                // TODO: Reset, if EnableBuffering is enabled since we read the magic bytes
                // section.Body.Seek(0, SeekOrigin.Begin);
                
                var blobContainerClient = new BlobContainerClient("<redacted>", "<redacted>");
                var blobClient = blobContainerClient.GetBlobClient($"{customerId}/{documentId}/{trustedFileName}");
                await blobClient.UploadAsync(section.Body, new BlobUploadOptions
                {
                    HttpHeaders = new BlobHttpHeaders
                    {
                        ContentType = section.ContentType
                    }
                }, ct);
            }
            else if (contentDisposition.HasFormDataContentDisposition())
            {
                var encoding = GetEncoding(section);
                if (encoding is null)
                {
                    ModelState.AddModelError("File", "Couldn't detect encoding of the file contents.");
                    _logger.LogInformation("Encoding of file for customer {CustomerId} with id {DocumentId} couldn't be detected", customerId, documentId);
                    return BadRequest(ModelState);
                }
            }
            
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            section = await reader.ReadNextSectionAsync(ct);
        }
        
        return Ok();
    }
    
    public static string GetBoundary(MediaTypeHeaderValue contentType, int lengthLimit)
    {
        var boundary = HeaderUtilities.RemoveQuotes(contentType.Boundary).Value;

        if (string.IsNullOrWhiteSpace(boundary))
        {
            throw new InvalidDataException("Missing content-type boundary.");
        }

        if (boundary.Length > lengthLimit)
        {
            throw new InvalidDataException(
                $"Multipart boundary length limit {lengthLimit} exceeded.");
        }

        return boundary;
    }
    
    private static Encoding? GetEncoding(MultipartSection section)
    {
        var hasMediaTypeHeader = 
            MediaTypeHeaderValue.TryParse(section.ContentType, out var mediaType);

        // UTF-7 is insecure and shouldn't be honored. UTF-8 succeeds in most cases.
        if (!hasMediaTypeHeader || Encoding.UTF7.Equals(mediaType.Encoding))
        {
            return Encoding.UTF8;
        }

        return mediaType.Encoding;
    }
}

public static class ContentDispositionHeaderValueExtensions
{
    public static bool HasFileContentDisposition(this ContentDispositionHeaderValue contentDisposition)
    {
        return contentDisposition != null &&
               contentDisposition.DispositionType.Equals("form-data") &&
               (!string.IsNullOrEmpty(contentDisposition.FileName.Value) ||
                !string.IsNullOrEmpty(contentDisposition.FileNameStar.Value));
    }
    
    public static bool HasFormDataContentDisposition(this ContentDispositionHeaderValue contentDisposition)
    {
        return contentDisposition != null &&
               contentDisposition.DispositionType.Equals("form-data") &&
               string.IsNullOrEmpty(contentDisposition.FileName.Value) &&
               string.IsNullOrEmpty(contentDisposition.FileNameStar.Value);
    }
}

public class MultiPartRequest
{
    public string Stuff { get; set; }
}
