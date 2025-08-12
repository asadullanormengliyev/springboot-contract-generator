package uz.zero_one.project

import jakarta.transaction.Transactional
import org.apache.coyote.BadRequestException
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.text.PDFTextStripper
import org.apache.poi.xwpf.usermodel.XWPFDocument
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.web.multipart.MultipartFile
import org.xhtmlrenderer.pdf.ITextRenderer
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Paths
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

interface AdminService {
    fun create(request: AdminCreateRequest)
}

interface UserService {
    fun create(request: UserCreateRequest)
    fun getOne(id: Long): GetOneUser
    fun getAllDirectors(pageable: Pageable): Page<GetOneUser>
    fun delete(id: Long)
    fun login(username: String, password: String): JwtResponseDto
    fun update(id: Long, updateDto: UserUpdateDto)
    fun getUserByUsername(username: String): UserDto
    fun getAllOperators(pageable: Pageable): Page<GetOneUser>
    fun getUsersByOrganisationId(id: Long): List<GetOneUser>
    fun getAllDirectorsByOrganisationId(id: Long): List<GetOneUser>
    fun userStatus(id: Long, request: UserStatusUpdateRequest)
    fun userRoleUpdate(id: Long, request: UserRoleUpdateRequest)
    fun getAllFilter(
        status: Status?,
        role: UserRole?,
        username: String?,
        fullName: String?,
        lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser>

    fun findByUserName(username: String): UserDto
    fun getAllUsersFilter(status: Status?, fullName: String?, lastName: String?, pageable: Pageable): Page<UserDto>
    fun getAllOperatorsByOrganisationAndTemplate(
        userId: Long,
        templateId: Long,
        search: String?,
        pageable: Pageable
    ): Page<OperatorWithPermissionDto>

    fun updatePassword(id: Long, newPassword: String, confirmPassword: String)
    fun getAllOperatorsByOrganisationAndContract(
        userId: Long,
        contractId: Long,
        search: String?,
        pageable: Pageable
    ): Page<OperatorWithPermissionDto>
}

interface OrganisationService {
    fun create(request: OrganisationCreateRequest): OrganisationResponse
    fun getAllFiltered(name: String?, address: String?, pageable: Pageable): Page<GetOneOrganisation>
    fun update(id: Long, update: OrganisationUpdate)
    fun delete(id: Long)
    fun get(id: Long): GetOneOrganisation
    fun searchAddress(address: String): List<GetOneOrganisation>
    fun searchByNameLike(name: String): List<GetOneOrganisation>
    fun getAllUserByOrganisationIdFilterStatusAndUsername(
        organisationId: Long?,
        status: Status?,
        username: String?,
        fullName: String?,
        lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser>

    fun findUsersByOrganisationIdAndFilters(
        userId: Long,
        userRole: UserRole?,
        fullName: String?,
        status: Status?,
        pageable: Pageable
    ): Page<GetOneUser>
}

interface TemplateService {
    fun saveFile(title: String, file: MultipartFile, userId: Long)
    fun getAll(pageable: Pageable): Page<GetOneTemplate>
    fun getOne(id: Long): GetOneTemplate
    fun getTemplateKeysByTemplateId(id: Long): List<GetTemplateKeyDto>
    fun getTemplateFileBytes(templateId: Long): File
    fun deleteTemplate(id: Long)
    fun updateTemplate(id: Long, request: UpdateTemplateDto)
    fun getAllTemplateAndSearch(title: String?, pageable: Pageable): Page<GetOneTemplate>
    fun updateTemplateKeyStatuses(requests: UpdateTemplateKeyEnabledRequest)
}

interface ContractService {
    fun createContract(request: CreateContractRequest, id: Long)
    fun getOneContract(id: Long): GetOneContract
    fun getAllContract(pageable: Pageable): Page<GetOneContract>
    fun generateContract(contractIds: List<Long>, format: String, userId: Long)
    fun searchContracts(title: String?, pageable: Pageable): Page<GetOneContract>
    fun deleteContract(id: Long)
    fun updateContract(contractId: Long, request: UpdateContractRequest)
    fun getContractValueByContractId(contractId: Long): List<GetContractValueAndTemplateKeyDto>
    fun getContractFileBytes(contractId: Long): File
    fun getAllContractsByOrganisation(
        name: String?,
        title: String?,
        pageable: Pageable
    ): Page<ContractsByOrganizationDto>

    fun getAllContractsSearchOrganisation(search: String?, pageable: Pageable): Page<ContractsByOrganizationDto>
}

interface ContractAssignmentService {
    fun assignContractToOperator(
        contractId: Long,
        request: ContractAssignRequest,
        assignedById: Long
    ): PermissionCountResponse

    fun getAllOperatorByContractId(contractId: Long): List<UserWithPermissionDto>
}

interface DownloadHistoryService {
    fun getMyDownloads(downloadStatus: DownloadStatus?,format: String?, userId: Long, pageable: Pageable): Page<DownloadHistoryResponse>
    fun getById(id: Long): File
}

interface TemplateAssignmentService {
    fun assignTemplateToOperator(
        templateId: Long,
        request: TemplateAssignRequest,
        assignedById: Long
    ): PermissionCountResponse

    fun getAllOperatorByTemplate(templateId: Long): List<UserWithPermissionDto>
    fun searchTemplatesByOperatorIdAndTitle(operatorId: Long, title: String?, pageable: Pageable): Page<GetOneTemplate>
}

@Service
class AdminServiceImpl(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
) : AdminService {

    override fun create(request: AdminCreateRequest) {
        request.run {
            val encode = passwordEncoder.encode(password)
            val user = User(fullName, lastName, username, encode, role, status = Status.ACTIVE)
            userRepository.save(user)
        }
    }

}

@Service
class OrganisationServiceImpl(
    private val organisationRepository: OrganisationRepository,
    private val userRepository: UserRepository
) : OrganisationService {

    override fun create(request: OrganisationCreateRequest): OrganisationResponse {
        if (organisationRepository.existsByNameAndDeletedFalse(request.name)) {
            throw OrganisationNameExistsException(request.name)
        }
        val organisation = organisationRepository.save(
            Organisation(
                name = request.name,
                address = request.address
            )
        )
        return OrganisationResponse.toResponse(organisation)
    }

    override fun getAllFiltered(
        name: String?,
        address: String?,
        pageable: Pageable
    ): Page<GetOneOrganisation> {
        val spec: Specification<Organisation> =
            OrganisationSpecification.notDeleted()
                .and(OrganisationSpecification.nameLike(name))
                .and(OrganisationSpecification.addressEqual(address))

        return organisationRepository.findAll(spec, pageable).map { GetOneOrganisation.toResponse(it) }

    }

    override fun update(
        id: Long,
        update: OrganisationUpdate
    ) {
        val organisation = organisationRepository.findByIdAndDeletedFalse(id) ?: throw OrganisationNotFoundException(id)
        update.run {
            name?.let { organisation.name = it }
            address?.let { organisation.address = it }
        }
        organisationRepository.save(organisation)
    }

    override fun delete(id: Long) {
        organisationRepository.trash(id) ?: throw OrganisationNotFoundException(id)
    }

    override fun get(id: Long): GetOneOrganisation {
        val organisation = organisationRepository.findByIdAndDeletedFalse(id)
        return organisation?.let { GetOneOrganisation.toResponse(it) } ?: throw OrganisationNotFoundException(id)
    }

    override fun searchAddress(address: String): List<GetOneOrganisation> {
        val searchOrganisationByAddress = organisationRepository.searchOrganisationByAddress(address)
        return searchOrganisationByAddress.map { organisation -> GetOneOrganisation.toResponse(organisation) }
    }

    override fun searchByNameLike(name: String): List<GetOneOrganisation> {
        return organisationRepository.searchByNameLike(name)
            .map { organisation -> GetOneOrganisation.toResponse(organisation) }
    }

    override fun getAllUserByOrganisationIdFilterStatusAndUsername(
        organisationId: Long?,
        status: Status?,
        username: String?,
        fullName: String?,
        lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser> {
        var spec: Specification<User>? = UserSpecification.fromOrganisationWithAllowedRoles(organisationId)
        UserSpecification.statusEquals(status)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.usernameLike(username)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.fullNameLike(fullName)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.lastNameLike(lastName)?.let {
            spec = spec?.and(it) ?: it
        }

        return userRepository.findAll(spec, pageable).map { user -> GetOneUser.toResponse(user) }
    }

    override fun findUsersByOrganisationIdAndFilters(
        userId: Long,
        userRole: UserRole?,
        fullName: String?,
        status: Status?,
        pageable: Pageable
    ): Page<GetOneUser> {
        val organisation =
            userRepository.findOrganisationByUserId(userId) ?: throw OrganisationNotFoundException(userId)
        var spec: Specification<User>? = UserSpecification.fromOrganisationWithAllowedRoles(organisation.id)
        UserSpecification.statusEquals(status)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.nameLike(fullName)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.desc().let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.roleEquals(userRole)?.let {
            spec = spec?.and(it) ?: it
        }
        return userRepository.findAll(spec, pageable).map { user -> GetOneUser.toResponse(user) }
    }

}

@Service
class UserServiceImpl(
    private val userRepository: UserRepository,
    private val organisationRepository: OrganisationRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val templateAssignmentRepository: TemplateAssignmentRepository,
    private val contractAssignmentRepository: ContractAssignmentRepository
) : UserService {

    override fun create(request: UserCreateRequest) {
        val organisation = organisationRepository.findByIdAndDeletedFalse(request.organisationId)
            ?: throw OrganisationNotFoundException(request.organisationId)
        if (userRepository.existsByUsername(request.username)){
            throw UserNameAlreadyExistsException(request.username)
        }
        request.run {
            val encodePassword = passwordEncoder.encode(request.password)
            val user = User(
                fullName,
                lastName,
                username,
                encodePassword,
                role = UserRole.OPERATOR,
                status = Status.ACTIVE,
                organisation
            )
            userRepository.save(user)
        }
    }

    fun add(request: UserRequest, userId: Long) {
        val organisation =
            userRepository.findOrganisationByUserId(userId) ?: throw OrganisationNotFoundException(userId)
        if (userRepository.existsByUsername(request.username)){
            throw UserNameAlreadyExistsException(request.username)
        }
        request.run {
            val encodePassword = passwordEncoder.encode(request.password)
            val user = User(
                fullName,
                lastName,
                username,
                encodePassword,
                role = UserRole.OPERATOR,
                status = Status.ACTIVE,
                organisation
            )
            userRepository.save(user)
        }
    }

    override fun getOne(id: Long): GetOneUser {
        val user = userRepository.findByIdAndDeletedFalse(id)
        return user?.let { GetOneUser.toResponse(it) } ?: throw UserNotFoundException(id)
    }

    override fun getAllDirectors(pageable: Pageable): Page<GetOneUser> {
        return userRepository.findAllDirectors(pageable).map { GetOneUser.toResponse(it) }
    }

    override fun delete(id: Long) {
        userRepository.trash(id) ?: throw UserNotFoundException(id)
    }

    override fun login(username: String, password: String): JwtResponseDto {
        val user1 = userRepository.findByUsernameAndDeletedFalse(username) ?: throw UserNameNotFoundException(username)
        if (user1.role == UserRole.USER) {
            throw ForbiddenRoleException(user1.role)
        }
        val matches = passwordEncoder.matches(password, user1.password)
        if (!matches) {
            throw PasswordNotFoundException(password)
        }
        val generateAccessToken = jwtService.generateAccessToken(user1)
        val generateRefreshToken = jwtService.generateRefreshToken(user1)

        return JwtResponseDto(generateAccessToken, generateRefreshToken)
    }

    override fun update(id: Long, updateDto: UserUpdateDto) {
        val user = userRepository.findByIdAndDeletedFalse(id) ?: throw UserNotFoundException(id)
        updateDto.run {
            fullName?.let { user.fullName = it }
            lastName?.let { user.lastName = it }
            username?.let { user.username = it }
            password?.let {
                val encode = passwordEncoder.encode(it)
                user.password = encode
            }
        }
        userRepository.save(user)
    }

    override fun getUserByUsername(username: String): UserDto {
        val user = userRepository.findByUsernameAndDeletedFalse(username)
            ?: throw UsernameNotFoundException(username)
        return UserDto.toResponse(user)
    }

    override fun getAllOperators(pageable: Pageable): Page<GetOneUser> {
        return userRepository.findAllOperators(pageable).map { user -> GetOneUser.toResponse(user) }
    }

    override fun getUsersByOrganisationId(id: Long): List<GetOneUser> {
        if (!organisationRepository.organisationIdAndDeletedFalse(id)) {
            throw OrganisationNotActiveException(id)
        }
        return userRepository.getAllUsersByOrganisation(id).map { user -> GetOneUser.toResponse(user) }
    }

    override fun getAllDirectorsByOrganisationId(id: Long): List<GetOneUser> {
        if (!organisationRepository.organisationIdAndDeletedFalse(id)) {
            throw OrganisationNotActiveException(id)
        }
        return userRepository.getAllDirectorsByOrganisationId(id).map { user -> GetOneUser.toResponse(user) }
    }

    override fun userStatus(id: Long, request: UserStatusUpdateRequest) {
        val user = userRepository.findByIdAndDeletedFalse(id) ?: throw UserNotFoundException(id)
        user.status = request.status
        userRepository.save(user)
    }

    override fun userRoleUpdate(id: Long, request: UserRoleUpdateRequest) {
        val user = userRepository.findByIdAndDeletedFalse(id) ?: throw UserNotFoundException(id)
        user.role = request.role
        userRepository.save(user)
    }

    override fun getAllFilter(
        status: Status?,
        role: UserRole?,
        username: String?,
        fullName: String?,
        lastName: String?,
        pageable: Pageable
    ): Page<GetOneUser> {
        var spec: Specification<User>? = null
        UserSpecification.statusEquals(status)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.roleEquals(role)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.usernameLike(username)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.fullNameLike(fullName)?.let {
            spec = spec?.and(it) ?: it
        }
        UserSpecification.lastNameLike(lastName)?.let {
            spec = spec?.and(it) ?: it
        }
        return userRepository.findAll(spec, pageable).map { user -> GetOneUser.toResponse(user) }
    }

    override fun findByUserName(username: String): UserDto {
        val user = userRepository.findByUsername(username) ?: throw UsernameNotFoundException(username)
        return UserDto.toResponse(user)
    }

    override fun getAllUsersFilter(
        status: Status?,
        fullName: String?,
        lastName: String?,
        pageable: Pageable
    ): Page<UserDto> {
        val spec: Specification<User> =
            UserSpecification.isNotDeleted()
                .and(UserSpecification.statusEquals(status))
                .and(UserSpecification.fullNameLike(fullName))
                .and(UserSpecification.lastNameLike(lastName))
                .and(UserSpecification.desc())
        return userRepository.findAll(spec, pageable).map { user -> UserDto.toResponse(user) }
    }

    override fun getAllOperatorsByOrganisationAndTemplate(
        userId: Long,
        templateId: Long,
        search: String?,
        pageable: Pageable
    ): Page<OperatorWithPermissionDto> {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val organisation = userRepository.findOrganisationByUserId(user.id!!) ?: throw OrganisationNotFoundException(
            user.organisation?.id
        )

        val usersPage = userRepository.getAllOperatorsByOrganisationAndTemplate(templateId, organisation.id!!, search, pageable)

        return usersPage.map { operator ->
            val assignment = templateAssignmentRepository.findByTemplateIdAndOperatorId(templateId, operator.id!!)
            val allPermissions = PermissionType.entries.toSet()
            val permissionsMap = allPermissions.associateWith { perm ->
                assignment?.permissions?.contains(perm) ?: false
            }

            val granted = permissionsMap.values.count { it }
            val total = allPermissions.size

            OperatorWithPermissionDto(
                id = operator.id!!,
                fullName = operator.fullName,
                lastName = operator.lastName,
                username = operator.username,
                role = operator.role.name,
                status = operator.status,
                organisationId = operator.organisation?.id!!,
                permissions = permissionsMap,
                permissionCountResponse = PermissionCountResponse(
                    totalPermission = total,
                    grantedPermissions = granted
                )
            )
        }
    }

    override fun updatePassword(id: Long, newPassword: String, confirmPassword: String) {
        userRepository.findByIdAndDeletedFalse(id)
            ?.also {
                if (newPassword != confirmPassword)
                    throw PasswordMismatchException(newPassword, confirmPassword)
            }?.apply {
                password = passwordEncoder.encode(newPassword)
            }?.also(userRepository::save)
            ?: throw UserNotFoundException(id)
    }

    override fun getAllOperatorsByOrganisationAndContract(
        userId: Long,
        contractId: Long,
        search: String?,
        pageable: Pageable
    ): Page<OperatorWithPermissionDto> {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val organisation = userRepository.findOrganisationByUserId(user.id!!) ?: throw OrganisationNotFoundException(
            user.organisation?.id
        )
        val users =
            userRepository.getAllOperatorsByOrganisationAndContract(contractId, organisation.id!!, search, pageable)
        return users.map { operator ->
            val assignment = contractAssignmentRepository.findByContractIdAndOperatorId(contractId, operator.id!!)
            val allPermissions = PermissionType.entries.toSet()
            val permissionsMap = allPermissions.associateWith { perm ->
                assignment?.permissions?.contains(perm) ?: false
            }

            val granted = permissionsMap.values.count { it }
            val total = allPermissions.size

            OperatorWithPermissionDto(
                id = operator.id!!,
                fullName = operator.fullName,
                lastName = operator.lastName,
                username = operator.username,
                role = operator.role.name,
                status = operator.status,
                organisationId = operator.organisation?.id!!,
                permissions = permissionsMap,
                permissionCountResponse = PermissionCountResponse(
                    totalPermission = total,
                    grantedPermissions = granted
                )
            )
        }
    }

}

@Service
class TemplateServiceImpl(
    private val templateRepository: TemplateRepository,
    private val templateKeyRepository: TemplateKeyRepository,
    private val userRepository: UserRepository
) : TemplateService {

    override fun saveFile(title: String, file: MultipartFile, userId: Long) {
        val organisation =
            userRepository.findOrganisationByUserId(userId) ?: throw OrganisationNotFoundException(userId)
        if (templateRepository.existsByTitleAndOrganisationId(title,organisation.id!!)){
            throw TemplateTitleAlreadyExistsException(title)
        }
        if (file.size > 5*1024*1024) {
            throw FileSizeExceededException(file.size)
        }
        val originalName = file.originalFilename ?: "file.docx"
        val extension = originalName.substringAfterLast(".").lowercase()
        val uploadDir =
            File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/templates")
        if (!uploadDir.exists()) uploadDir.mkdirs()

        val filePath = Paths.get(uploadDir.path, originalName).toString()
        val destinationFile = File(filePath)
        file.transferTo(destinationFile)
        val template = Template(
            title = title,
            filePath = filePath,
            organisation = organisation
        )
        templateRepository.save(template)

        val keys = when (extension) {
            "docx" -> extractKeysFromDocx(destinationFile)
            "txt" -> extractKeysFromTxt(destinationFile)
            "pdf" -> extractKeysFromPdf(destinationFile)
            "word" -> extractKeysFromWord(destinationFile)
            else -> emptyList()
        }

        keys.forEach { keyName ->
            templateKeyRepository.save(
                TemplateKey(
                    keyName = keyName,
                    template = template,
                    enabled = true
                )
            )
        }

    }

    override fun getAll(pageable: Pageable): Page<GetOneTemplate> {
        val templates = templateRepository.findAllNotDeleted(pageable)
        return templates.map { template -> GetOneTemplate.toResponse(template) }
    }

    override fun getOne(id: Long): GetOneTemplate {
        val template = templateRepository.findByIdAndDeletedFalse(id) ?: throw TemplateNotFoundException(id)
        return GetOneTemplate.toResponse(template)
    }

    private fun extractKeysFromDocx(file: File): List<String> {
        val keys = mutableSetOf<String>()
        val document = XWPFDocument(FileInputStream(file))
        val pattern = "\\{[^}]+\\}".toRegex()
        val allText = StringBuilder()
        document.paragraphs.forEach { para ->
            allText.append(para.text).append(" ")
        }
        document.tables.forEach { table ->
            table.rows.forEach { row ->
                row.tableCells.forEach { cell ->
                    allText.append(cell.text).append(" ")
                }
            }
        }
        document.close()
        pattern.findAll(allText.toString()).forEach { match ->
            keys.add(match.value)
        }
        return keys.toList()
    }

    private fun extractKeysFromWord(file: File): List<String> {
        val keys = mutableSetOf<String>()
        val document = XWPFDocument(FileInputStream(file))
        val pattern = "\\{[^}]+\\}".toRegex()
        val allText = StringBuilder()
        document.paragraphs.forEach { para ->
            allText.append(para.text).append(" ")
        }
        document.tables.forEach { table ->
            table.rows.forEach { row ->
                row.tableCells.forEach { cell ->
                    allText.append(cell.text).append(" ")
                }
            }
        }
        document.close()
        pattern.findAll(allText.toString()).forEach { match ->
            keys.add(match.value)
        }
        return keys.toList()
    }

    private fun extractKeysFromTxt(file: File): List<String> {
        val keys = mutableSetOf<String>()
        val pattern = "\\{[^}]+\\}".toRegex()
        file.forEachLine { line ->
            val matcher = pattern.findAll(line)
            matcher.forEach { matchResult ->
                keys.add(matchResult.value)
            }
        }
        return keys.toList()
    }

    private fun extractKeysFromPdf(file: File): List<String> {
        val keys = mutableSetOf<String>()
        val pattern = "\\{[^}]+\\}".toRegex()
        PDDocument.load(file).use { document ->
            val pdfText = PDFTextStripper().getText(document)
            pattern.findAll(pdfText).forEach { result ->
                keys.add(result.value)
            }
        }
        return keys.toList()
    }

    override fun getTemplateKeysByTemplateId(id: Long): List<GetTemplateKeyDto> {
        return templateKeyRepository.findAllByTemplateId(id).map { key -> GetTemplateKeyDto.toResponse(key) }
    }

    override fun getTemplateFileBytes(templateId: Long): File {
        val template = templateRepository.findByIdAndDeletedFalse(templateId)
            ?: throw TemplateNotFoundException(templateId)

        val file = File(template.filePath)
        if (!file.exists()) {
            throw RuntimeException("Fayl topilmadi: ${template.filePath}")
        }
        return file
    }

    override fun deleteTemplate(id: Long) {
        templateRepository.trash(id) ?: throw TemplateNotFoundException(id)
    }

    @Transactional
    override fun updateTemplate(id: Long, request: UpdateTemplateDto) {
        val template = templateRepository.findByIdAndDeletedFalse(id) ?: throw TemplateNotFoundException(id)
        request.run {
            title?.let { template.title = it }
            file?.let { file ->
                if (file.size > 5*1024*1024) {
                    throw FileSizeExceededException(file.size)
                }
                val originalName = file.originalFilename ?: "updated_file.docx"
                val extension = originalName.substringAfterLast(".").lowercase()
                val uploadDir =
                    File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/templates")
                if (!uploadDir.exists()) {
                    uploadDir.mkdirs()
                }
                val oldFile = File(template.filePath)
                if (oldFile.exists()) oldFile.delete()

                val newFilePath = Paths.get(uploadDir.absolutePath, originalName).toString()
                val destinationFile = File(newFilePath)
                file.transferTo(destinationFile)

                template.filePath = newFilePath
                templateKeyRepository.softDeleteAllByTemplateId(template.id!!)

                val keys = when (extension) {
                    "docx" -> extractKeysFromDocx(destinationFile)
                    "txt" -> extractKeysFromTxt(destinationFile)
                    "pdf" -> extractKeysFromPdf(destinationFile)
                    "word" -> extractKeysFromWord(destinationFile)
                    else -> emptyList()
                }

                keys.forEach { keyName ->
                    templateKeyRepository.save(
                        TemplateKey(
                            keyName = keyName,
                            template = template,
                            enabled = true
                        )
                    )
                }
            }
        }
        templateRepository.save(template)
    }

    override fun getAllTemplateAndSearch(
        title: String?,
        pageable: Pageable
    ): Page<GetOneTemplate> {
        val auth = SecurityContextHolder.getContext().authentication
        val userId = auth.details as Long
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val spec: Specification<Template> =
            TemplateSpecification.notDeleted()
                .and(TemplateSpecification.getAll(user))
                .and(TemplateSpecification.titleSearch(title))
                .and(TemplateSpecification.desc())
        return templateRepository.findAll(spec, pageable).map { template -> GetOneTemplate.toResponse(template) }
    }

    @Transactional
    override fun updateTemplateKeyStatuses(request: UpdateTemplateKeyEnabledRequest) {
        val key =
            templateKeyRepository.findByIdAndDeletedFalse(request.templateKeyId) ?: throw TemplateKeyNotFoundException(
                request.templateKeyId
            )
        key.enabled = request.enabled
        templateKeyRepository.save(key)
    }

    fun findByTemplateKeyByTemplateId(templateKeyId: Long): Template {
        return templateKeyRepository.findTemplateKeyByTemplateId(templateKeyId) ?: throw TemplateKeyNotFoundException(
            templateKeyId
        )
    }

}

@Service
class ContractServiceImpl(
    private val contractRepository: ContractRepository,
    private val templateRepository: TemplateRepository,
    private val templateKeyRepository: TemplateKeyRepository,
    private val userRepository: UserRepository,
    private val contractValueRepository: ContractValueRepository,
    private val downloadHistoryRepository: DownloadHistoryRepository
) : ContractService {

    private fun fillTemplate(template: Template, values: List<ContractValueRequest>): File {
        val inputFile = File(template.filePath)
        val doc = XWPFDocument(FileInputStream(inputFile))

        val keyMap = values.associate { it.templateKeyId to it.value }
        val templateKeys = templateKeyRepository.findAllByTemplateId(template.id!!)
            .associateBy { it.id!! }
        doc.paragraphs.forEach { para ->
            val fullText = para.runs.joinToString("") { it.text() ?: "" }
            var newText = fullText
            templateKeys.forEach { (id, key) ->
                val value = keyMap[id]
                if (value != null) {
                    newText = newText.replace(key.keyName, value)
                }
            }
            if (fullText != newText) {
                while (para.runs.size > 0) {
                    para.removeRun(0)
                }
                para.createRun().setText(newText)
            }
        }

        doc.tables.forEach { table ->
            table.rows.forEach { row ->
                row.tableCells.forEach { cell ->
                    cell.paragraphs.forEach { para ->
                        val fullText = para.runs.joinToString("") { it.text() ?: "" }
                        var newText = fullText
                        templateKeys.forEach { (id, key) ->
                            val value = keyMap[id]
                            if (value != null) {
                                newText = newText.replace(key.keyName, value)
                            }
                        }
                        if (fullText != newText) {
                            while (para.runs.size > 0) {
                                para.removeRun(0)
                            }
                            para.createRun().setText(newText)
                        }
                    }
                }
            }
        }

        val outputDir =
            File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/contracts")
        if (!outputDir.exists()) outputDir.mkdirs()
        val outputFile = File(outputDir, "contract_${UUID.randomUUID()}.docx")
        FileOutputStream(outputFile).use { out -> doc.write(out) }
        doc.close()
        return outputFile
    }

    @Transactional
    override fun createContract(request: CreateContractRequest, id: Long) {
        val template = templateRepository.findByIdAndDeletedFalse(request.templateId)
            ?: throw TemplateNotFoundException(request.templateId)

        val operator = userRepository.findByIdAndDeletedFalse(id)
            ?: throw UserNotFoundException(id)
        val organisation =
            userRepository.findOrganisationByUserId(operator.id!!) ?: throw OrganisationNotFoundException(operator.id)

        val endsWith = template.filePath.endsWith(".pdf", true)
        val filledFile = if (endsWith) {
            fillPdfWithTextReplace(template, request.values)
        } else {
            fillTemplate(template, request.values)
        }

        val contract = contractRepository.save(
            Contract(
                template = template,
                operator = operator,
                filePath = filledFile.absolutePath,
                organisation = organisation,
                values = listOf()
            )
        )

        val templateKeys = templateKeyRepository.findAllById(
            request.values.map { it.templateKeyId }
        ).associateBy { it.id }

        val contractValues = request.values.mapNotNull { dto ->
            val templateKey = templateKeys[dto.templateKeyId] ?: return@mapNotNull null

            val value = dto.value?.trim()

            if (templateKey.enabled && (value == null || value.isBlank())) {
                throw BadRequestException("Qiymat kerak: ${templateKey.keyName}")
            }

            if (!templateKey.enabled && (value == null || value.isBlank())) {
                return@mapNotNull ContractValue(
                    value = templateKey.keyName,
                    templateKey = templateKey,
                    contract = contract
                )
            }

            ContractValue(
                value = value ?: "",
                templateKey = templateKey,
                contract = contract
            )
        }

        contractValueRepository.saveAll(contractValues)

    }

    fun extractTextFromPdf(file: File): String {
        PDDocument.load(file).use { document ->
            return PDFTextStripper().getText(document)
        }
    }

    fun replaceMarkers(content: String, values: Map<String, String>): String {
        val pattern = "\\{[^}]+\\}".toRegex()
        return pattern.replace(content) { matchResult ->
            val rawKey = matchResult.value
            val cleanKey = rawKey.removePrefix("{").removeSuffix("}")
            values[cleanKey] ?: "N/A"
        }
    }

    fun generatePdfFromHtml(html: String): File {
        val outputDir =
            File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/contracts")
        if (!outputDir.exists()) outputDir.mkdirs()

        val outputFile = File(outputDir, "contract_${UUID.randomUUID()}.pdf")
        val outputStream = FileOutputStream(outputFile)
        val renderer = ITextRenderer()
        renderer.setDocumentFromString(html)
        renderer.layout()
        renderer.createPDF(outputStream)
        outputStream.close()
        return outputFile
    }

    fun fillPdfWithTextReplace(template: Template, values: List<ContractValueRequest>): File {
        val keyMap = values.associate { it.templateKeyId to it.value }
        val templateKeys = templateKeyRepository.findAllByTemplateId(template.id!!)
            .associateBy { it.id!! }
        val valueMap = templateKeys.values.associate { key ->
            val cleanKey = key.keyName.removePrefix("{").removeSuffix("}")
            cleanKey to (keyMap[key.id] ?: "N/A")
        }
        val pdfText = extractTextFromPdf(File(template.filePath))
        val replacedText = replaceMarkers(pdfText, valueMap)
        val escapedText = escapeHtml(replacedText)
        val htmlContent = """
        <html>
        <head><style>body { font-family: sans-serif; }</style></head>
        <body>
            <pre>$escapedText</pre>
        </body>
        </html>
        """.trimIndent()
        return generatePdfFromHtml(htmlContent)
    }

    fun escapeHtml(content: String): String {
        return content
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    }

    override fun getOneContract(id: Long): GetOneContract {
        val contract = contractRepository.findByIdWithValues(id) ?: throw ContractNotFoundException(id)
        return GetOneContract.toResponse(contract)
    }

    override fun getAllContract(pageable: Pageable): Page<GetOneContract> {
        TODO("Not yet implemented")
    }

    override fun generateContract(
        contractIds: List<Long>,
        format: String,
        userId: Long
    ) {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val outputDir = File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/generated")
        if (!outputDir.exists()) outputDir.mkdirs()

        val generatedFiles = mutableListOf<File>()
        val contracts = mutableListOf<Contract>()
        contractIds.forEach { contractId ->
            val contract = contractRepository.findByIdAndDeletedFalse(contractId)
                ?: return@forEach

            val docxFile = File(contract.filePath)
            if (!docxFile.exists()) return@forEach

            val process = ProcessBuilder(
                "libreoffice",
                "--headless",
                "--convert-to", format,
                docxFile.absolutePath,
                "--outdir", outputDir.absolutePath
            ).start()
            val exitCode = process.waitFor()

            if (exitCode == 0) {
                val generatedFile = File(outputDir, docxFile.name.replaceAfterLast(".", format))
                if (generatedFile.exists()) {
                    generatedFiles.add(generatedFile)
                    contracts.add(contract)
                }
            }
        }

        val createZip = createZipFile(generatedFiles)
        downloadHistoryRepository.save(
            DownloadHistory(
                contracts = contracts,
                format = format,
                filePath = createZip.absolutePath,
                user = user,
                downloadStatus = DownloadStatus.COMPLETED
            )
        )
    }

    private fun createZipFile(files: List<File>): File {
        val zipFile = File("/home/asadulla/IdeaProjects/Spring/SpringFramework/SpringBoot/Kotlin/project/uploads/zip${UUID.randomUUID()}.zip")
        ZipOutputStream(FileOutputStream(zipFile)).use { zipOutputStream ->
            files.forEach { file ->
                FileInputStream(file).use { fil ->
                    val zipEntry = ZipEntry(file.name)
                    zipOutputStream.putNextEntry(zipEntry)
                    fil.copyTo(zipOutputStream)
                    zipOutputStream.closeEntry()
                }
            }
        }
        return zipFile
    }

    override fun searchContracts(
        title: String?,
        pageable: Pageable
    ): Page<GetOneContract> {

        val auth = SecurityContextHolder.getContext().authentication
        val userId = auth.details as Long
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        var spec: Specification<Contract> = ContractSpecification.notDeleted()
        ContractSpecification.templateTitleLike(title)?.let { spec = spec.and(it) }
        spec = spec.and(ContractSpecification.byUser(user))
        spec = spec.and(ContractSpecification.desc())

        return contractRepository.findAll(spec, pageable)
            .map { contract -> GetOneContract.toResponse(contract) }
    }

    override fun deleteContract(id: Long) {
        contractRepository.trash(id) ?: throw ContractNotFoundException(id)
    }

    override fun updateContract(contractId: Long, request: UpdateContractRequest) {
        val contract = contractRepository.findByIdAndDeletedFalse(contractId)
            ?: throw ContractNotFoundException(contractId)

        request.values.forEach { dto ->
            val contractValue = contractValueRepository.findById(dto.contractValueId)
                .orElseThrow { ContractValueNotFoundException(dto.contractValueId) }

            contractValue.value = dto.value
            contractValueRepository.save(contractValue)
        }

        val oldFile = File(contract.filePath)
        if (oldFile.exists()) {
            oldFile.delete()
        }

        val allValues = contractValueRepository.findAllByContractId(contract.id!!)
        val updatedFile = fillTemplate(
            contract.template,
            allValues.map {
                ContractValueRequest(it.templateKey.id!!, it.value)
            }
        )
        contract.filePath = updatedFile.absolutePath
        contractRepository.save(contract)
    }

    override fun getContractValueByContractId(contractId: Long): List<GetContractValueAndTemplateKeyDto> {
        val contractValues = contractValueRepository.findAllByContractIds(contractId)
        return contractValues.map { value -> GetContractValueAndTemplateKeyDto.toResponse(value) }
    }

    override fun getContractFileBytes(contractId: Long): File {
        val contract =
            contractRepository.findByIdAndDeletedFalse(contractId) ?: throw ContractNotFoundException(contractId)
        val file = File(contract.filePath)
        if (!file.exists()) {
            throw FileNotFoundException(contractId)
        }
        return file
    }

    override fun getAllContractsByOrganisation(
        name: String?,
        title: String?,
        pageable: Pageable
    ): Page<ContractsByOrganizationDto> {
        val contracts = contractRepository.getAllContractsByOrganisation(name, title, pageable)
        return contracts.map { contract -> ContractsByOrganizationDto.toResponse(contract) }
    }

    override fun getAllContractsSearchOrganisation(
        search: String?,
        pageable: Pageable
    ): Page<ContractsByOrganizationDto> {
        val contracts = contractRepository.getAllContractsSearchByOrganisation(search, pageable)
        return contracts.map { contract -> ContractsByOrganizationDto.toResponse(contract) }
    }

}

@Service
class ContractAssignmentServiceImpl(
    private val userRepository: UserRepository,
    private val contractRepository: ContractRepository,
    private val contractAssignmentRepository: ContractAssignmentRepository
) : ContractAssignmentService {

    override fun assignContractToOperator(
        contractId: Long,
        request: ContractAssignRequest,
        assignedById: Long
    ): PermissionCountResponse {
        val contract =
            contractRepository.findByIdAndDeletedFalse(contractId) ?: throw ContractNotFoundException(contractId)
        val operator = userRepository.findByIdAndDeletedFalse(request.operatorId)
            ?: throw UserNotFoundException(request.operatorId)
        val user = userRepository.findByIdAndDeletedFalse(assignedById) ?: throw UserNotFoundException(assignedById)

        var assignment = contractAssignmentRepository.findByContractIdAndOperatorId(contractId, operator.id!!)
        if (assignment == null) {
            assignment = ContractAssignment(
                contract = contract,
                operator = operator,
                assignedBy = user,
                permissions = mutableSetOf()
            )
        }

        request.permissions.forEach { dto ->
            if (dto.enabled) {
                assignment.permissions.add(dto.permission)
            } else {
                assignment.permissions.remove(dto.permission)
            }
        }

        contractAssignmentRepository.save(assignment)
        val totalPermissions = PermissionType.entries.size
        val grantedPermissions = assignment.permissions.size
        return PermissionCountResponse(totalPermissions, grantedPermissions)
    }

    override fun getAllOperatorByContractId(contractId: Long): List<UserWithPermissionDto> {
        val assignments = contractAssignmentRepository.findAllByContractIdWithOperator(contractId)
        return assignments.map { UserWithPermissionDto.fromAssignment(it) }
    }

    fun getOperatorAssignedContract(userId: Long): OperatorAssignedContractResponse {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val organisation = userRepository.findOrganisationByUserId(user.id!!) ?: throw OrganisationNotFoundException(user.organisation?.id)
        val contracts = contractRepository.findAllByOrganisationId(organisation.id!!)
        val assignments = contractAssignmentRepository.findAllByContractByOperator(userId)

        val assignedDtos = contracts.map { contract ->
            val assignment = assignments.firstOrNull { it.contract.id == contract.id }
            val permissionsMap = if (contract.operator.id == userId) {
                PermissionType.entries.associateWith { true }
            } else {
                PermissionType.entries.associateWith { perm ->
                    assignment?.permissions?.contains(perm) ?: false
                }
            }
            OperatorAssignedContractDto(
                contractId = contract.id!!,
                permissions = permissionsMap
            )
        }

        return OperatorAssignedContractResponse(assignedDtos)
    }

}

@Service
class DownloadHistoryServiceImpl(
    private val downloadHistoryRepository: DownloadHistoryRepository,
    private val userRepository: UserRepository
) : DownloadHistoryService {

    override fun getMyDownloads(
        downloadStatus: DownloadStatus?,
        format: String?,
        userId: Long,
        pageable: Pageable
    ): Page<DownloadHistoryResponse> {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val organisation = userRepository.findOrganisationByUserId(user.id!!) ?: throw OrganisationNotFoundException(
            user.organisation?.id
        )
        val spec: Specification<DownloadHistory> =
            DownloadHistorySpecification.notDeleted()
                .and(DownloadHistorySpecification.statusEquals(downloadStatus))
                .and(DownloadHistorySpecification.byUserOrganisationId(organisation.id!!))
                .and(DownloadHistorySpecification.ascend())
                .and(DownloadHistorySpecification.format(format))
        return downloadHistoryRepository.findAll(spec, pageable)
            .map { response -> DownloadHistoryResponse.from(response) }
    }

    override fun getById(id: Long): File {
        val file = downloadHistoryRepository.findByIdAndDeletedFalse(id) ?: throw FileNotFoundException(id)
        val file1 = File(file.filePath)
        if (!file1.exists()) {
            throw FileNotFoundException(id)
        }
        return file1
    }

}

@Service
class TemplateAssignedServiceImpl(
    private val templateRepository: TemplateRepository,
    private val userRepository: UserRepository,
    private val templateAssignmentRepository: TemplateAssignmentRepository) : TemplateAssignmentService {

    override fun assignTemplateToOperator(
        templateId: Long,
        request: TemplateAssignRequest,
        assignedById: Long
    ): PermissionCountResponse {
        val template =
            templateRepository.findByIdAndDeletedFalse(templateId) ?: throw TemplateNotFoundException(templateId)
        val operator = userRepository.findByIdAndDeletedFalse(request.operatorId)
            ?: throw UserNotFoundException(request.operatorId)
        val user = userRepository.findByIdAndDeletedFalse(assignedById) ?: throw UserNotFoundException(assignedById)

        var assignment = templateAssignmentRepository.findByTemplateIdAndOperatorId(templateId, operator.id!!)
        if (assignment == null) {
            assignment = TemplateAssignment(
                template = template,
                operator = operator,
                assignedBy = user,
                permissions = mutableSetOf()
            )
        }

        request.permissions.forEach { dto ->
            if (dto.enabled) {
                assignment.permissions.add(dto.permission)
            } else {
                assignment.permissions.remove(dto.permission)
            }
        }
        templateAssignmentRepository.save(assignment)

        val totalPermissions = PermissionType.entries.size
        val grantedPermissions = assignment.permissions.size

        return PermissionCountResponse(totalPermissions, grantedPermissions)
    }

    override fun getAllOperatorByTemplate(templateId: Long): List<UserWithPermissionDto> {
        val templateAssignments = templateAssignmentRepository.findAllByTemplateIdWithOperator(templateId)
        return templateAssignments.map { assignment -> UserWithPermissionDto.fromTemplateAssignment(assignment) }
    }

    override fun searchTemplatesByOperatorIdAndTitle(
        operatorId: Long,
        title: String?,
        pageable: Pageable
    ): Page<GetOneTemplate> {
        val templates = templateAssignmentRepository.searchTemplatesByOperatorIdAndTitle(operatorId, title, pageable)
        return templates.map { template -> GetOneTemplate.toResponse(template) }
    }

    fun getOperatorAssignedTemplate(userId: Long): OperatorAssignedResponse {
        val user = userRepository.findByIdAndDeletedFalse(userId) ?: throw UserNotFoundException(userId)
        val organisation = userRepository.findOrganisationByUserId(user.id!!) ?: throw OrganisationNotFoundException(user.organisation?.id)

        val templates = templateRepository.findAllTemplateByOrganisationAndTemplateAssignment(organisation.id!!)
        val assignments = templateAssignmentRepository.findAllByTemplateByOperator(userId)

        val assignedDtos = templates.map { template ->
            val assignment = assignments.firstOrNull { it.template.id == template.id }

            val permissionsMap = PermissionType.entries.associateWith { perm ->
                assignment?.permissions?.contains(perm) ?: false
            }

            OperatorAssignedDto(
                templateId = template.id!!,
                permissions = permissionsMap
            )
        }

        return OperatorAssignedResponse(assigned = assignedDtos)
    }

}

@Service
class PermissionService(
    private val contractAssignmentRepository: ContractAssignmentRepository,
    private val templateAssignmentRepository: TemplateAssignmentRepository
) {

    fun checkContractPermission(operatorId: Long, contractId: Long, permissionType: PermissionType) {
        val assignment = contractAssignmentRepository.findByContractIdAndOperatorId(contractId, operatorId)
            ?: throw AccessDeniedException(contractId, operatorId)
        if (permissionType !in assignment.permissions) {
            throw OperatorPermissionException(permissionType)
        }
    }

    fun checkTemplatePermission(operatorId: Long, templateId: Long, permissionType: PermissionType) {
        val assignment = templateAssignmentRepository.findByTemplateIdAndOperatorId(templateId, operatorId)
            ?: throw AccessDeniedException(templateId, operatorId)
        if (permissionType !in assignment.permissions) {
            throw OperatorPermissionException(permissionType)
        }
    }

}