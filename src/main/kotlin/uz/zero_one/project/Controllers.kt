package uz.zero_one.project

import org.springframework.context.support.ResourceBundleMessageSource
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.http.ContentDisposition
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile
import java.io.File
import java.security.Principal

@RestControllerAdvice
class ExceptionHandlers(
    private val errorMessageSource: ResourceBundleMessageSource
) {
    @ExceptionHandler(DemoExceptions::class)
    fun handleException(exceptions: DemoExceptions): ResponseEntity<*> {
        return when (exceptions) {
            is UserNameAlreadyExistsException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.username))

            is UserNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is OrganisationNameExistsException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.name))

            is OrganisationNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is UserNameNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.username))

            is TemplateNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is ContractNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is OrganisationNotActiveException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is PasswordNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.password))

            is FileNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource, exceptions.id))

            is TemplateKeyNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.id))
            is ContractValueNotFoundException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.id))

            is ForbiddenRoleException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.role))

            is AccessDeniedException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.contractId,exceptions.operatorId))
            is OperatorPermissionException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.permissionType))

            is PasswordMismatchException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.newPassword,exceptions.confirmPassword))

            is TemplateTitleAlreadyExistsException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.title))

            is FileSizeExceededException -> ResponseEntity.badRequest()
                .body(exceptions.getErrorMessage(errorMessageSource,exceptions.size))
        }
    }
}

@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val userServiceImpl: UserServiceImpl
) {

    @PostMapping("/login")
    fun login(@RequestParam username: String, @RequestParam password: String): JwtResponseDto {
        return userServiceImpl.login(username, password)
    }

    @GetMapping("/me")
    fun getCurrentUserInfo(principal: Principal): UserDto {
        return userServiceImpl.getUserByUsername(principal.name)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR','ADMIN')")
    @PatchMapping("/users/{id}/status")
    fun updateUserStatus(@PathVariable id: Long, @RequestBody request: UserStatusUpdateRequest) {
        userServiceImpl.userStatus(id, request)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR','ADMIN')")
    @PatchMapping("/users/{id}/role")
    fun updateUserRole(@PathVariable id: Long, @RequestBody request: UserRoleUpdateRequest) {
        userServiceImpl.userRoleUpdate(id, request)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR','ADMIN')")
    @PatchMapping("/{id}/update-password")
    fun updatePassword(@PathVariable id: Long,
                       @RequestParam newPassword: String,
                       @RequestParam confirmPassword: String){
        userServiceImpl.updatePassword(id,newPassword,confirmPassword)
    }

}

@RestController
@RequestMapping("/api/v1/organisation")
class OrganisationController(private val organisationService: OrganisationServiceImpl) {

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/add")
    fun create(@RequestBody request: OrganisationCreateRequest): OrganisationResponse {
        return organisationService.create(request)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/search")
    fun searchOrganisations(
        @RequestParam(required = false) name: String?,
        @RequestParam(required = false) address: String?,
        pageable: Pageable
    ): Page<GetOneOrganisation> {
        return organisationService.getAllFiltered(name, address, pageable)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/update/{id}")
    fun update(@PathVariable id: Long, @RequestBody update: OrganisationUpdate) {
        organisationService.update(id, update)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/delete/{id}")
    fun delete(@PathVariable id: Long) {
        organisationService.delete(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/get/{id}")
    fun getOne(@PathVariable id: Long): GetOneOrganisation {
        return organisationService.get(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/search-by-address")
    fun searchOrganisationAddress(@RequestParam address: String): List<GetOneOrganisation> {
        return organisationService.searchAddress(address)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/{id}/staff")
    fun getOrganisationStaff(
        @PathVariable id: Long,
        @RequestParam(required = false) status: Status?,
        @RequestParam(required = false) username: String?,
        @RequestParam(required = false) fullName: String?,
        @RequestParam(required = false) lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser> {
        return organisationService.getAllUserByOrganisationIdFilterStatusAndUsername(
            id, status, username, fullName, lastName, pageable
        )
    }

}

@RestController
@RequestMapping("/api/v1/admin")
class AdminController(
    private val userService: UserServiceImpl,
    private val adminServiceImpl: AdminServiceImpl,
    private val contractServiceImpl: ContractServiceImpl
) {

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/add")
    fun create(@RequestBody request: UserCreateRequest) {
        userService.create(request)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/getOne/{id}")
    fun getOne(@PathVariable id: Long): GetOneUser {
        return userService.getOne(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/getAllDirector")
    fun getAll(pageable: Pageable): Page<GetOneUser> {
        return userService.getAllDirectors(pageable)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/delete/{id}")
    fun delete(@PathVariable id: Long) {
        userService.delete(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/update/{id}")
    fun update(@PathVariable id: Long,@RequestBody updateDto: UserUpdateDto) {
        userService.update(id, updateDto)
    }

    @PostMapping("/register")
    fun register(@RequestBody adminCreateRequest: AdminCreateRequest) {
        adminServiceImpl.create(adminCreateRequest)
    }

    @GetMapping("/organisation/{organisationId}/users")
    fun getUsersByOrganisationId(@PathVariable organisationId: Long): List<GetOneUser> {
        return userService.getUsersByOrganisationId(organisationId)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/organisation/{id}/directors")
    fun getAllDirectorsByOrganisationId(@PathVariable id: Long): List<GetOneUser> {
        return userService.getAllDirectorsByOrganisationId(id)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/search")
    fun searchUser(
        @RequestParam(required = false) status: Status?,
        @RequestParam(required = false) role: UserRole?,
        @RequestParam(required = false) username: String?,
        @RequestParam(required = false) fullName: String?,
        @RequestParam(required = false) lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser> {
        return userService.getAllFilter(status, role, username, fullName, lastName, pageable)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/contracts/view/{contractId}")
    fun viewContract(@PathVariable contractId: Long): ResponseEntity<ByteArray>{
        val file = contractServiceImpl.getContractFileBytes(contractId)
        val readBytes = file.readBytes()
        val mediaType = getMediaType(file.extension)
        val headers = HttpHeaders().apply {
            contentType = mediaType
            contentDisposition = ContentDisposition
                .inline()
                .filename(file.name)
                .build()
        }

        return ResponseEntity.ok()
            .headers(headers)
            .body(readBytes)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/organizations-name/contracts")
    fun getContractsByOrganization(@RequestParam(required = false) name: String?,
        @RequestParam(required = false) title: String?,
                                     pageable: Pageable): Page<ContractsByOrganizationDto>{
        return contractServiceImpl.getAllContractsByOrganisation(name,title,pageable)
    }

    @GetMapping("/organizations/contracts")
    fun getAllContractsSearchOrganisation(@RequestParam(required = false) search: String?,
                                          pageable: Pageable): Page<ContractsByOrganizationDto>{
        return contractServiceImpl.getAllContractsSearchOrganisation(search,pageable)
    }

    fun getMediaType(extension: String): MediaType = when (extension) {
        "pdf" -> MediaType.APPLICATION_PDF
        "docx" -> MediaType("application", "vnd.openxmlformats-officedocument.wordprocessingml.document")
        "txt" -> MediaType.TEXT_PLAIN
        "csv" -> MediaType("text", "csv")
        else -> MediaType.APPLICATION_OCTET_STREAM
    }

}

@RestController
@RequestMapping("/api/v1/director")
class DirectorController(
    private val userService: UserServiceImpl,
    private val templateService: TemplateServiceImpl,
    private val templateAssignedServiceImpl: TemplateAssignedServiceImpl,
    private val permissionService: PermissionService,
    private val securityUtils: SecurityUtils
) {

    @PreAuthorize("hasAnyRole('DIRECTOR')")
    @PostMapping("/add")
    fun create(@RequestBody request: UserRequest) {
        val userId = SecurityContextHolder.getContext().authentication.details as Long
        userService.add(request,userId)
    }

    @PreAuthorize("hasRole('DIRECTOR')")
    @GetMapping("/getOne/{id}")
    fun getOne(@PathVariable id: Long): GetOneUser {
        return userService.getOne(id)
    }

    @PreAuthorize("hasRole('DIRECTOR')")
    @GetMapping("/getAll")
    fun getAll(pageable: Pageable): Page<GetOneUser> {
        return userService.getAllOperators(pageable)
    }

    @PreAuthorize("hasRole('DIRECTOR')")
    @DeleteMapping("/delete/{id}")
    fun delete(@PathVariable id: Long) {
        userService.delete(id)
    }

    @PreAuthorize("hasRole('DIRECTOR')")
    @PostMapping("/upload")
    fun uploadTemplate(
        @RequestParam("title") title: String,
        @RequestParam("file") file: MultipartFile,
    ) {
        templateService.saveFile(title, file,securityUtils.getCurrentUserId())
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/getAllTemplate")
    fun getAllTemplateAndSearch(
        @RequestParam(required = false) search: String?,
        pageable: Pageable
    ): Page<GetOneTemplate> {
        return templateService.getAllTemplateAndSearch(search, pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/getOneTemplate/{id}")
    fun getOneTemplate(@PathVariable id: Long): GetOneTemplate {
        return templateService.getOne(id)
    }

    @PreAuthorize("hasAnyRole('DIRECTOR','ADMIN')")
    @PutMapping("/update/{id}")
    fun update(@PathVariable id: Long,@RequestBody updateDto: UserUpdateDto) {
        userService.update(id, updateDto)
    }

    @PreAuthorize("hasRole('DIRECTOR')")
    @GetMapping("/getAllUsersFilter")
    fun getAllUsersFilter(
        @RequestParam(required = false) status: Status?,
        @RequestParam(required = false) fullName: String?,
        @RequestParam(required = false) lastName: String?,
        pageable: Pageable
    ): Page<UserDto> {
        return userService.getAllUsersFilter(status, fullName, lastName, pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/templates/view/{templateId}")
    fun viewTemplate(@PathVariable templateId: Long): ResponseEntity<ByteArray> {
        securityUtils.checkPermissionTemplateIfOperator(permissionService,templateId, PermissionType.READ)
        val file = templateService.getTemplateFileBytes(templateId)
        val readBytes = file.readBytes()
        val extension = file.extension.lowercase()
        val mediaType = getMediaType(extension)

        val headers = HttpHeaders().apply {
            contentType = mediaType
            contentDisposition = ContentDisposition
                .inline()
                .filename(file.name)
                .build()
        }

        return ResponseEntity.ok()
            .headers(headers)
            .body(readBytes)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @DeleteMapping("delete/{id}/template")
    fun deleteTemplate(@PathVariable id: Long) {
        securityUtils.checkPermissionTemplateIfOperator(permissionService,id, PermissionType.DELETE)
        templateService.deleteTemplate(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PostMapping("/templates/{templateId}/assign")
    fun assignTemplate(
        @PathVariable templateId: Long,
        @RequestBody request: TemplateAssignRequest
    ): PermissionCountResponse {
        val userId = securityUtils.getCurrentUserId()
        return templateAssignedServiceImpl.assignTemplateToOperator(templateId,request,userId)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PutMapping("/update/{id}/template")
    fun updateTemplate(
        @PathVariable id: Long,
        @RequestParam(required = false, value = "title") title: String?,
        @RequestParam(required = false, value = "file") file: MultipartFile?
    ) {
        securityUtils.checkPermissionTemplateIfOperator(permissionService,id, PermissionType.UPDATE)
        val request = UpdateTemplateDto(title, file)
        templateService.updateTemplate(id, request)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PutMapping("/template-keys/status")
    fun updateStatus(@RequestBody requests: UpdateTemplateKeyEnabledRequest) {
        val template = templateService.findByTemplateKeyByTemplateId(requests.templateKeyId)
        securityUtils.checkPermissionTemplateIfOperator(permissionService,template.id!!, PermissionType.SWITCH)
        templateService.updateTemplateKeyStatuses(requests)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-operator-by-organisation")
    fun getAllOperatorByOrganisationAndTemplate(@RequestParam templateId: Long, @RequestParam(required = false) search: String?, pageable: Pageable): Page<OperatorWithPermissionDto>{
        val userId = securityUtils.getCurrentUserId()
        return userService.getAllOperatorsByOrganisationAndTemplate(userId,templateId,search,pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-operator-by-organisation-contract")
    fun getAllOperatorByOrganisationAndContract(@RequestParam contractId: Long,@RequestParam(required = false) search: String?,pageable: Pageable): Page<OperatorWithPermissionDto>{
        val userId = securityUtils.getCurrentUserId()
       return userService.getAllOperatorsByOrganisationAndContract(userId,contractId,search,pageable)
    }

    fun getMediaType(extension: String): MediaType = when (extension) {
        "pdf" -> MediaType.APPLICATION_PDF
        "docx" -> MediaType("application", "vnd.openxmlformats-officedocument.wordprocessingml.document")
        "txt" -> MediaType.TEXT_PLAIN
        "csv" -> MediaType("text", "csv")
        else -> MediaType.APPLICATION_OCTET_STREAM
    }

}

@RestController
@RequestMapping("/api/v1/operator")
class OperatorController(
    private val templateService: TemplateServiceImpl,
    private val contractService: ContractServiceImpl,
    private val contractAssignmentServiceImpl: ContractAssignmentServiceImpl,
    private val downloadHistoryServiceImpl: DownloadHistoryServiceImpl,
    private val organisationServiceImpl: OrganisationServiceImpl,
    private val permissionService: PermissionService,
    private val templateAssignedServiceImpl: TemplateAssignedServiceImpl,
    private val securityUtils: SecurityUtils
) {

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/getAllTemplate")
    fun getAllTemplate(pageable: Pageable): Page<GetOneTemplate> {
        return templateService.getAll(pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/getOneTemplate/{id}")
    fun getOneTemplate(@PathVariable id: Long): GetOneTemplate {
        return templateService.getOne(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/keys/{id}")
    fun getTemplateKeys(@PathVariable id: Long): List<GetTemplateKeyDto> {
        return templateService.getTemplateKeysByTemplateId(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PostMapping("/create")
    fun createContract(@RequestBody request: CreateContractRequest) {
        securityUtils.checkPermissionTemplateIfOperator(permissionService,request.templateId, PermissionType.CREATE)
        contractService.createContract(request, securityUtils.getCurrentUserId())
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/contracts")
    fun searchContracts(
        @RequestParam(required = false) title: String?,
        pageable: Pageable
    ): Page<GetOneContract> {
        return contractService.searchContracts(title, pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PostMapping("/contracts/{contractId}/assign")
    fun assignContract(
        @PathVariable contractId: Long,
        @RequestBody request: ContractAssignRequest
    ): PermissionCountResponse {
        val userId = securityUtils.getCurrentUserId()
       return contractAssignmentServiceImpl.assignContractToOperator(contractId,request,userId)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PostMapping("/contracts/generate")
    fun generateMultipleContracts(
        @RequestBody request: GenerateRequest,
    ): ResponseEntity<String> {
        val userId = SecurityContextHolder.getContext().authentication.details as Long
        contractService.generateContract(request.contractIds, request.format, userId)
        return ResponseEntity.ok("Generatsiya yakunlandi.")
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/downloads/my")
    fun getMyDownloads(@RequestParam(required = false) status: DownloadStatus?,
                       @RequestParam(required = false) format: String?,
                       pageable: Pageable): ResponseEntity<Page<DownloadHistoryResponse>> {
        val userId = securityUtils.getCurrentUserId()
        val result = downloadHistoryServiceImpl.getMyDownloads(status,format,userId,pageable)
        return ResponseEntity.ok(result)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/downloads/{id}/download")
    fun downloadGeneratedFile(@PathVariable id: Long): ResponseEntity<ByteArray> {
        val download = downloadHistoryServiceImpl.getById(id)
        val file = File(download.absolutePath)
        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_OCTET_STREAM
            contentDisposition = ContentDisposition.attachment()
                .filename(file.name)
                .build()
        }
        return ResponseEntity.ok()
            .headers(headers)
            .body(file.readBytes())
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @DeleteMapping("/delete-contract/{id}")
    fun deleteContract(@PathVariable id: Long){
        contractService.deleteContract(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/contracts-value/{id}")
    fun getContractValueByContractId(@PathVariable id: Long): List<GetContractValueAndTemplateKeyDto>{
        return contractService.getContractValueByContractId(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @PutMapping("/update-contract/{id}")
    fun updateContract(@PathVariable id: Long,@RequestBody request: UpdateContractRequest){
        contractService.updateContract(id,request)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-operator-assigned/{id}")
    fun getAllOperatorByContractAssigned(@PathVariable id: Long): List<UserWithPermissionDto>{
       return contractAssignmentServiceImpl.getAllOperatorByContractId(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-operator-template-assigned/{id}")
    fun getAllByOperatorByTemplatedAssigned(@PathVariable id: Long): List<UserWithPermissionDto>{
        return templateAssignedServiceImpl.getAllOperatorByTemplate(id)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/users/by-organisation")
    fun findUsersByOrganisationIdAndFilters(@RequestParam(required = false) fullName: String?,
                                            @RequestParam(required = false) status: Status?,
                                            @RequestParam(required = false) role: UserRole?,
                                            pageable: Pageable): Page<GetOneUser>{
        val userId = securityUtils.getCurrentUserId()
       return organisationServiceImpl.findUsersByOrganisationIdAndFilters(userId,role,fullName,status,pageable)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-assigned-operator")
    fun getOperatorAssignedTemplate(): OperatorAssignedResponse {
        val userId = securityUtils.getCurrentUserId()
        return templateAssignedServiceImpl.getOperatorAssignedTemplate(userId)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-assigned-contract-operator")
    fun getOperatorAssignedContract(): OperatorAssignedContractResponse{
        val userId = securityUtils.getCurrentUserId()
        return contractAssignmentServiceImpl.getOperatorAssignedContract(userId)
    }

    @PreAuthorize("hasAnyRole('OPERATOR', 'DIRECTOR')")
    @GetMapping("/get-assigned-template-by-search")
    fun getAllAssignedTemplateBySearchTitle(@RequestParam(required = false) title: String?,pageable: Pageable): Page<GetOneTemplate>{
        val userId = securityUtils.getCurrentUserId()
        return templateAssignedServiceImpl.searchTemplatesByOperatorIdAndTitle(userId,title,pageable)
    }

}
